use anyhow::{bail, ensure};
use log::*;
use ocl::{Buffer, Device, Platform, ProQue};
use pgp::types::PublicKeyTrait;
use rand::thread_rng;
use std::{
    collections::HashSet,
    fs,
    path::Path,
    sync::{mpsc::*, LazyLock},
    thread,
    time::Instant,
};
use utils::ARGS;
use utils::*;

mod utils;

/// Numbers of words returned by the kernel: timestamp and pattern match mask.
const RESULT_WORDS: usize = 2;
/// The match mask is a u32, so this many patterns can be searched at once.
const MAX_PATTERNS: usize = 32;

/// A pattern together with the key packets it is matched against.
struct ActivePattern {
    pattern: HashPattern,
    targets: Vec<KeyTarget>,
}

/// Where one key packet's padded hash data lives in the shared buffer.
struct TargetLayout {
    target: KeyTarget,
    /// Word offset in the concatenated hash data.
    offset: usize,
    /// Number of 512-bit SHA-1 blocks.
    chunks: usize,
}

/// Everything the GPU has to do for one search round.
struct SearchPlan {
    /// Key packets to hash, each with the indices of the patterns matched on it.
    target_patterns: Vec<(KeyTarget, Vec<usize>)>,
    layout: Vec<TargetLayout>,
    total_words: usize,
    /// Reciprocal of the probability that any active pattern matches a nonce.
    possibility: f64,
}

impl SearchPlan {
    /// SHA-1 evaluations per nonce.
    fn work_per_nonce(&self) -> u64 {
        self.layout.len() as u64
    }

    /// Expected number of SHA-1 evaluations until a match.
    fn estimate_hashes(&self) -> Option<f64> {
        if self.possibility.is_finite() && self.possibility > 0.0 {
            Some(self.possibility * self.work_per_nonce() as f64)
        } else {
            None
        }
    }
}

/// Group the active patterns by key packet and lay out the hash data.
fn build_plan(patterns: &[ActivePattern], key: &VanitySecretKey) -> anyhow::Result<SearchPlan> {
    ensure!(!patterns.is_empty(), "No pattern to search for");
    ensure!(
        patterns.len() <= MAX_PATTERNS,
        "At most {MAX_PATTERNS} patterns can be searched at once"
    );

    // A stable order, so the generated code and the match mask always agree.
    let mut target_patterns: Vec<(KeyTarget, Vec<usize>)> = Vec::new();
    for target in [KeyTarget::Primary, KeyTarget::Sign, KeyTarget::Encrypt] {
        let indices: Vec<usize> = patterns
            .iter()
            .enumerate()
            .filter(|(_, active)| active.targets.contains(&target))
            .map(|(index, _)| index)
            .collect();
        if !indices.is_empty() {
            target_patterns.push((target, indices));
        }
    }
    ensure!(!target_patterns.is_empty(), "No key packet to search");

    let mut layout = Vec::with_capacity(target_patterns.len());
    let mut offset = 0;
    for (target, _) in &target_patterns {
        let words = manually_prepare_sha1(key.hashdata_for(*target));
        layout.push(TargetLayout {
            target: *target,
            offset,
            chunks: words.len() / 16,
        });
        offset += words.len();
    }

    // Every key packet of a pattern is an independent chance to match it.
    // Computed in log space: for very hard patterns `1 - p` rounds to 1 and the
    // estimate would otherwise become infinite.
    let log_miss_all: f64 = patterns
        .iter()
        .map(|active| {
            let hit = 1.0 / active.pattern.possibility;
            // ln(1 - hit), accurate for tiny hit.
            (-hit).ln_1p() * active.targets.len() as f64
        })
        .sum();
    let possibility = if log_miss_all >= 0.0 {
        f64::INFINITY
    } else {
        // 1 / (1 - exp(log_miss_all)) = 1 / -expm1(log_miss_all)
        1.0 / (-log_miss_all.exp_m1())
    };

    Ok(SearchPlan {
        target_patterns,
        layout,
        total_words: offset,
        possibility,
    })
}

/// Prepare the padded SHA-1 input of every searched packet, back to back.
fn prepare_hashdata(key: &VanitySecretKey, plan: &SearchPlan) -> anyhow::Result<Vec<u32>> {
    let mut all = Vec::with_capacity(plan.total_words);
    for layout in &plan.layout {
        let part = manually_prepare_sha1(key.hashdata_for(layout.target));
        ensure!(
            part.len() == layout.chunks * 16,
            "The {} unexpectedly changed its packet length, refusing to search",
            layout.target.label()
        );
        all.extend_from_slice(&part);
    }
    ensure!(all.len() == plan.total_words, "Unexpected hash data length");
    Ok(all)
}

/// The SHA-1 code for one key packet. The returned block is left open, so the
/// caller can put the pattern checks inside it and close it afterwards.
fn sha1_block(index: usize, offset: usize, chunks: usize) -> String {
    format!(
        r#"        // key packet #{index}
        {{
            uint h{index}[5] = {{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}};
            #pragma unroll
            for (uint chunk{index} = 0; chunk{index} < {chunks}; chunk{index}++) {{
                uint w{index}[80];
                for (int j = 0; j < 16; j++) w{index}[j] = data[{offset} + chunk{index} * 16 + j];
                for (int j = 16; j < 80; j++) w{index}[j] = ROTL(w{index}[j - 3] ^ w{index}[j - 8] ^ w{index}[j - 14] ^ w{index}[j - 16], 1);

                uint a{index} = h{index}[0];
                uint b{index} = h{index}[1];
                uint c{index} = h{index}[2];
                uint d{index} = h{index}[3];
                uint e{index} = h{index}[4];
                uint f{index};
                uint k{index};
                uint t{index};

                #pragma unroll
                for (int j = 0; j < 80; j++) {{
                    if (j < 20) {{
                        f{index} = d{index} ^ (b{index} & (c{index} ^ d{index}));
                        k{index} = 0x5A827999;
                    }} else if (j < 40) {{
                        f{index} = b{index} ^ c{index} ^ d{index};
                        k{index} = 0x6ED9EBA1;
                    }} else if (j < 60) {{
                        f{index} = (b{index} & c{index}) | (b{index} & d{index}) | (c{index} & d{index});
                        k{index} = 0x8F1BBCDC;
                    }} else {{
                        f{index} = b{index} ^ c{index} ^ d{index};
                        k{index} = 0xCA62C1D6;
                    }}
                    t{index} = ROTL(a{index}, 5) + f{index} + e{index} + k{index} + w{index}[j];
                    e{index} = d{index};
                    d{index} = c{index};
                    c{index} = ROTL(b{index}, 30);
                    b{index} = a{index};
                    a{index} = t{index};
                }}

                h{index}[0] += a{index};
                h{index}[1] += b{index};
                h{index}[2] += c{index};
                h{index}[3] += d{index};
                h{index}[4] += e{index};
            }}
"#
    )
}

/// Emit the code that hashes every searched packet, matches all patterns and
/// reports the timestamp plus the bit mask of the matched patterns.
fn generate_target_checks(plan: &SearchPlan, patterns: &[ActivePattern]) -> String {
    let mut body = String::new();

    // Every key packet shares the same creation timestamp, which sits right
    // after the packet header (word 1 of that packet's hash data).
    for layout in &plan.layout {
        body.push_str(&format!("        data[{}] = ts;\n", layout.offset + 1));
    }
    body.push_str("        uint mask = 0u;\n");

    for (index, (_, pattern_indices)) in plan.target_patterns.iter().enumerate() {
        let layout = &plan.layout[index];
        body.push_str(&sha1_block(index, layout.offset, layout.chunks));
        for &pattern_index in pattern_indices {
            // The filter was generated for `h`; point it at this packet's hash.
            let filter = patterns[pattern_index]
                .pattern
                .filter
                .replace("h[", &format!("h{index}["));
            body.push_str(&format!(
                "            if ({filter}) mask |= {}u;\n",
                1u32 << pattern_index
            ));
        }
        body.push_str("        }\n");
    }

    body.push_str(
        "        if (mask) {\n            result[0] = ts;\n            result[1] = mask;\n            break;\n        }\n",
    );

    body
}

/// Build the OpenCL program for a plan.
fn build_program(
    device: Device,
    dimension: usize,
    plan: &SearchPlan,
    patterns: &[ActivePattern],
) -> anyhow::Result<(ProQue, Buffer<u32>)> {
    let injects = [
        format!(
            "#define FUTURE_MODE ({})",
            if ARGS.future_timestamp { 1 } else { 0 }
        ),
        format!("#define TOTAL_WORDS ({})", plan.total_words),
    ];

    let pro_que = ProQue::builder()
        .src(
            std::include_str!("shader.cl")
                .replace("#define __INJECTS__", &injects.join("\n"))
                .replace(
                    "// __TARGET_CHECKS__",
                    &generate_target_checks(plan, patterns),
                ),
        )
        .device(device)
        .dims(dimension)
        .build()?;

    let buffer_result = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(RESULT_WORDS)
        .fill_val(0)
        .build()?;

    Ok((pro_que, buffer_result))
}

/// Resolve a selector against the packets the key actually has.
fn resolve_selector(
    key: &VanitySecretKey,
    selector: &TargetSelector,
) -> anyhow::Result<Vec<KeyTarget>> {
    if let TargetSelector::Targets(list) = selector {
        for target in list {
            // Gives a helpful error if the key has no such packet.
            key.resolve_target(*target)?;
        }
    }

    let targets = selector.expand(&key.available_targets());
    ensure!(!targets.is_empty(), "No key packet selected");
    Ok(targets)
}

/// Re-check the GPU's match on the CPU.
fn verify_matches(key: &VanitySecretKey, active: &[ActivePattern], mask: u32) -> Vec<usize> {
    let mut matched = Vec::new();

    for (index, active_pattern) in active.iter().enumerate() {
        if mask & (1u32 << index) == 0 {
            continue;
        }

        // A raw filter is only evaluated by the GPU, so there is no specific
        // packet to blame for the match.
        if active_pattern.pattern.raw {
            info!("Matched the raw --filter");
            matched.push(index);
            continue;
        }

        let mut found = None;
        for target in &active_pattern.targets {
            let fingerprint = key.fingerprint_for(*target);
            if active_pattern.pattern.is_match(fingerprint.as_bytes()) {
                found = Some((*target, hex::encode_upper(fingerprint.as_bytes())));
                break;
            }
        }

        match found {
            Some((target, fingerprint)) => {
                info!(
                    "Matched pattern \"{}\" on the {}: {}",
                    active_pattern.pattern.source,
                    target.label(),
                    fingerprint
                );
                matched.push(index);
            }
            None => warn!(
                "The GPU reported a match, but pattern \"{}\" matches none of its key packets; ignoring",
                active_pattern.pattern.source
            ),
        }
    }

    matched
}

fn main() -> anyhow::Result<()> {
    let bars = init_logger();

    debug!("{:#?}", LazyLock::force(&ARGS));

    let device_list = utils::DeviceList::new()?;

    if ARGS.list_device {
        info!("Available OpenCL devices: \n");
        for (i, device) in device_list.iter().enumerate() {
            println!("Device #{i} - {device:?}");
        }
        return Ok(());
    }

    let device = match ARGS.device {
        Some(i) => device_list[i].device,
        None => Device::first(Platform::default())?,
    };

    info!("Using device: {}", device.name()?);

    let dimension = match ARGS.thread {
        Some(v) => v,
        None => match device.info(ocl::core::DeviceInfo::MaxWorkItemSizes)? {
            ocl::core::DeviceInfoResult::MaxWorkItemSizes(wgs) => {
                let dimension = usize::max(wgs[0] * wgs[1], 1048576);
                info!("Auto set thread: {dimension}");
                dimension
            }
            _ => unreachable!(),
        },
    };

    let iteration = ARGS.iteration;

    // Determine the starting timestamp
    let start_timestamp = ARGS
        .start_timestamp
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    // Use the user-specified time range instead of dimension * iteration
    info!(
        "Starting search from {} and going {} in time{}",
        chrono::DateTime::from_timestamp(start_timestamp, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        if ARGS.future_timestamp {
            "forward"
        } else {
            "backward"
        },
        if ARGS.max_time_range.is_some() {
            format!(" (up to {} seconds)", ARGS.max_time_range.unwrap())
        } else {
            "".to_string()
        },
    );

    if ARGS.output.is_none() {
        if ARGS.no_secret_key_logging {
            warn!("No output dir given and you disabled secret key logging. You have no chance to save generated vanity keys.");
        } else {
            warn!("No output dir given. Generated vanity keys will not be saved.");
        }
    }

    if let Some(ref output_dir) = ARGS.output {
        warn!("Output directory does not exist, creating it: {output_dir}");
        fs::create_dir_all(output_dir)?;
    }

    // Patterns and the key packets they are matched against.
    let default_selector =
        TargetSelector::merge(&ARGS.algorithm)?.unwrap_or(TargetSelector::Targets(vec![ARGS
            .cipher_suite
            .default_target()]));
    let patterns: Vec<HashPattern> = ARGS
        .pattern
        .iter()
        .map(|pattern| pattern.parse())
        .collect::<anyhow::Result<_>>()?;

    if patterns.is_empty() && ARGS.filter.is_none() {
        bail!("No filter or pattern given");
    }
    if ARGS.shot_all && patterns.is_empty() {
        bail!("--shot-all needs at least one --pattern");
    }
    if ARGS.filter.is_some() && !patterns.is_empty() {
        warn!("--filter is set, so --pattern is ignored");
    }

    let mut rng = thread_rng();

    match ARGS.cipher_suite {
        CipherSuite::RSA2048 | CipherSuite::RSA3072 | CipherSuite::RSA4096 => {
            warn!("Generating RSA vanity keys is not recommended. Too slow!")
        }
        _ => (),
    };

    let mut vanity_key = VanitySecretKey::new(ARGS.cipher_suite, ARGS.user_id.clone(), &mut rng);

    let mut active: Vec<ActivePattern> = match &ARGS.filter {
        // A raw filter is one opaque pattern: the GPU decides, the CPU cannot
        // re-check it (the pattern has no constraints, so it always passes).
        Some(filter) => vec![ActivePattern {
            pattern: HashPattern::raw(filter.clone()),
            targets: resolve_selector(&vanity_key, &default_selector)?,
        }],
        None => patterns
            .into_iter()
            .map(|pattern| {
                let selector = pattern
                    .selector
                    .clone()
                    .unwrap_or_else(|| default_selector.clone());
                let targets = resolve_selector(&vanity_key, &selector)?;
                Ok(ActivePattern { pattern, targets })
            })
            .collect::<anyhow::Result<_>>()?,
    };

    // Set the initial timestamp for the key
    // Ensure we use the full timestamp value, not truncated
    let initial_timestamp = if start_timestamp > u32::MAX as i64 {
        // If timestamp is too large for u32, we need to handle this carefully
        // For now, use the current approach but ensure we're aware of the limitation
        warn!(
            "Timestamp {} is too large for u32, may cause unexpected behavior",
            start_timestamp
        );
        start_timestamp as u32
    } else {
        start_timestamp as u32
    };

    info!(
        "Using base timestamp: {} ({})",
        initial_timestamp,
        chrono::DateTime::from_timestamp(initial_timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );

    vanity_key.edit_timestamp(initial_timestamp, &mut rng);

    let mut plan = build_plan(&active, &vanity_key)?;
    let mut hashdata = prepare_hashdata(&vanity_key, &plan)?;

    info!(
        "Searching {} key packet(s) ({}) for {} pattern(s): {}",
        plan.layout.len(),
        plan.layout
            .iter()
            .map(|layout| layout.target.label())
            .collect::<Vec<_>>()
            .join(", "),
        active.len(),
        active
            .iter()
            .map(|active| active.pattern.source.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let (pro_que, buffer_result) = build_program(device, dimension, &plan, &active)?;
    let (tx_job, rx_job) = channel::<OpenClJob>();
    let (tx_result, rx_result) = channel::<Option<(u32, u32)>>();

    thread::spawn(move || opencl_thread(pro_que, buffer_result, rx_job, tx_result));

    let bench_size = std::cmp::min(
        (dimension * iteration) as u64,
        ARGS.max_time_range.map(|x| x as u64).unwrap_or(u64::MAX),
    );
    let bar = bars.add(init_progress_bar(plan.estimate_hashes()));

    let mut hashed: u64 = 0;
    let mut start = Instant::now();

    loop {
        debug!("Send key to OpenCL thread");
        tx_job.send(OpenClJob::Search { hashdata })?;

        let mut vanity_key_next =
            VanitySecretKey::new(ARGS.cipher_suite, ARGS.user_id.clone(), &mut rng);

        // Set the same initial timestamp for consistency
        vanity_key_next.edit_timestamp(initial_timestamp, &mut rng);

        debug!("Receive result from OpenCL thread");
        let vanity_result = rx_result.recv()?;

        let work = bench_size * plan.work_per_nonce();
        hashed += work;
        bar.inc(work);

        let elapsed = start.elapsed().as_secs_f64();

        let mut matched_patterns: Vec<usize> = Vec::new();
        if let Some((vanity_timestamp, mask)) = vanity_result {
            vanity_key.edit_timestamp(vanity_timestamp, &mut rng);
            matched_patterns = verify_matches(&vanity_key, &active, mask);
        }

        if !matched_patterns.is_empty() {
            vanity_key.log_state();

            match plan.estimate_hashes() {
                Some(estimate) => info!(
                    "Hashed: {} ({:.02}x) Time: {:.02}s Speed: {} hash/s",
                    format_number(hashed as f64),
                    (hashed as f64) / estimate,
                    elapsed,
                    format_number((hashed as f64) / elapsed),
                ),
                None => info!(
                    "Hashed: {} Time: {:.02}s Speed: {} hash/s",
                    format_number(hashed as f64),
                    elapsed,
                    format_number((hashed as f64) / elapsed),
                ),
            }

            if let Some(ref output_dir) = ARGS.output {
                fs::write(
                    Path::new(output_dir).join(format!(
                        "{}-sec.asc",
                        hex::encode_upper(vanity_key.secret_key.fingerprint().as_bytes())
                    )),
                    vanity_key.to_armored_string()?,
                )?;
            }

            if ARGS.oneshot {
                bar.finish();
                bars.clear()?;
                break;
            }

            if ARGS.shot_all {
                // Drop the patterns that just matched and search for the rest.
                let matched: HashSet<usize> = matched_patterns.into_iter().collect();
                active = active
                    .into_iter()
                    .enumerate()
                    .filter(|(index, _)| !matched.contains(index))
                    .map(|(_, active)| active)
                    .collect();

                if active.is_empty() {
                    bar.finish();
                    bars.clear()?;
                    break;
                }

                plan = build_plan(&active, &vanity_key)?;
                let (pro_que, buffer_result) = build_program(device, dimension, &plan, &active)?;
                tx_job.send(OpenClJob::Reconfigure {
                    pro_que,
                    buffer_result,
                })?;
                bar.set_length(plan.estimate_hashes().unwrap_or(1.0) as u64);
                info!(
                    "Still looking for {} pattern(s): {}",
                    active.len(),
                    active
                        .iter()
                        .map(|active| active.pattern.source.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            hashed = 0;
            bar.reset();
            start = Instant::now();
        } else if let Some(timeout) = ARGS.timeout {
            if elapsed > timeout {
                info!("Timeout!");
                break;
            }
        }

        vanity_key = vanity_key_next;
        hashdata = prepare_hashdata(&vanity_key, &plan)?;
    }

    Ok(())
}

/// Work for the OpenCL thread.
enum OpenClJob {
    /// Use a new program (the searched patterns changed).
    Reconfigure {
        pro_que: ProQue,
        buffer_result: Buffer<u32>,
    },
    Search {
        hashdata: Vec<u32>,
    },
}

fn opencl_thread(
    mut pro_que: ProQue,
    mut buffer_result: Buffer<u32>,
    rx_job: Receiver<OpenClJob>,
    tx_result: Sender<Option<(u32, u32)>>,
) {
    let mut vec = vec![0; RESULT_WORDS];
    debug!("OpenCL thread ready");

    while let Ok(job) = rx_job.recv() {
        let hashdata = match job {
            OpenClJob::Reconfigure {
                pro_que: new_pro_que,
                buffer_result: new_buffer_result,
            } => {
                pro_que = new_pro_que;
                buffer_result = new_buffer_result;
                continue;
            }
            OpenClJob::Search { hashdata } => hashdata,
        };

        buffer_result.cmd().fill(0, None).enq().unwrap();

        let buffer_hashdata = Buffer::<u32>::builder()
            .queue(pro_que.queue().clone())
            .len(hashdata.len())
            .copy_host_slice(&hashdata)
            .build()
            .unwrap();

        let kernel = pro_que
            .kernel_builder("vanity_sha1")
            .arg(&buffer_hashdata)
            .arg(&buffer_result)
            .arg(ARGS.iteration as u64)
            .arg(ARGS.max_time_range.unwrap_or(0))
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }

        buffer_result.read(&mut vec).enq().unwrap();

        tx_result
            .send(if vec[0] == 0 {
                None
            } else {
                Some((vec[0], vec[1]))
            })
            .unwrap();
    }

    debug!("OpenCL thread quit");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn key() -> VanitySecretKey {
        VanitySecretKey::new(
            CipherSuite::Ed25519,
            "Test <test@example.com>".into(),
            thread_rng(),
        )
    }

    #[test]
    fn every_target_of_a_pattern_is_an_extra_chance() {
        let pattern: HashPattern = "7777".parse().unwrap();
        let active = vec![ActivePattern {
            pattern,
            targets: vec![KeyTarget::Primary, KeyTarget::Encrypt],
        }];

        let plan = build_plan(&active, &key()).unwrap();
        assert_eq!(plan.layout.len(), 2);
        assert_eq!(plan.work_per_nonce(), 2);

        let expected = 1.0 / (1.0 - (1.0 - 16f64.powi(-4)).powi(2));
        assert!((plan.possibility - expected).abs() / expected < 1e-9);
    }

    #[test]
    fn patterns_or_within_a_packet() {
        let first: HashPattern = "1111".parse().unwrap();
        let second: HashPattern = "2222".parse().unwrap();
        let active = vec![
            ActivePattern {
                pattern: first,
                targets: vec![KeyTarget::Primary],
            },
            ActivePattern {
                pattern: second,
                targets: vec![KeyTarget::Primary],
            },
        ];

        let plan = build_plan(&active, &key()).unwrap();
        // Only one packet is hashed, but there are two chances to match it.
        assert_eq!(plan.work_per_nonce(), 1);
        let expected = 1.0 / (1.0 - (1.0 - 16f64.powi(-4)).powi(2));
        assert!((plan.possibility - expected).abs() / expected < 1e-9);
    }

    #[test]
    fn very_hard_patterns_still_have_an_estimate() {
        let pattern: HashPattern = "0123456789ABCDEF0123456789ABCDEF01234567".parse().unwrap();
        let active = vec![ActivePattern {
            pattern,
            targets: vec![KeyTarget::Primary],
        }];

        let plan = build_plan(&active, &key()).unwrap();
        let estimate = plan.estimate_hashes().expect("estimate missing");
        assert!(estimate > 1e40, "estimate was {estimate}");
        assert!(estimate.is_finite());
    }
}
