use anyhow::{bail, ensure, Context};
use log::*;
#[cfg(feature = "opencl")]
use ocl::{Buffer, Device, Platform, ProQue};
use pgp::types::{PublicKeyTrait, SecretParams};
use rand::{thread_rng, CryptoRng, Rng};
#[cfg(feature = "opencl")]
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{
    collections::HashSet,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex,
    },
    thread,
    time::Instant,
};
use utils::ARGS;
use utils::*;

mod utils;

/// Numbers of words returned by the kernel: timestamp, pattern match mask and
/// the index of the matched candidate (0 when not batched).
#[cfg(feature = "opencl")]
const RESULT_WORDS: usize = 3;
/// The match mask is a u32, so this many patterns can be searched at once.
const MAX_PATTERNS: usize = 32;
/// Timestamps the CPU backend scans per round.
const CPU_ROUND_TIMESTAMPS: u64 = 1 << 22;

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
///
/// `source` is a pointer expression to the packet's hash data (`data + N` for
/// the private copy, `hashdata + base` for batched searches). When
/// `inject_timestamp` is set, word 1 (the creation time) of the packet is
/// replaced with the candidate timestamp while hashing.
#[cfg(feature = "opencl")]
fn sha1_block(index: usize, source: &str, chunks: usize, inject_timestamp: bool) -> String {
    let timestamp_line = if inject_timestamp {
        format!("                if (chunk{index} == 0) w{index}[1] = ts;\n")
    } else {
        String::new()
    };
    format!(
        r#"        // key packet #{index}
        {{
            uint h{index}[5] = {{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}};
            #pragma unroll
            for (uint chunk{index} = 0; chunk{index} < {chunks}; chunk{index}++) {{
                uint w{index}[80];
                for (int j = 0; j < 16; j++) w{index}[j] = ({source})[chunk{index} * 16 + j];
{timestamp_line}                for (int j = 16; j < 80; j++) w{index}[j] = ROTL(w{index}[j - 3] ^ w{index}[j - 8] ^ w{index}[j - 14] ^ w{index}[j - 16], 1);

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
/// reports the timestamp, the bit mask of the matched patterns and, for
/// batched searches, which candidate key packet matched.
#[cfg(feature = "opencl")]
fn generate_target_checks(
    plan: &SearchPlan,
    patterns: &[ActivePattern],
    candidates: usize,
) -> String {
    let mut body = String::new();
    body.push_str("        uint mask = 0u;\n");

    if candidates > 1 {
        // Batched search: the same packet kind is hashed once per candidate,
        // all of them against the same timestamp, in a single launch.
        debug_assert_eq!(plan.layout.len(), 1, "batched searches hash one packet");
        let layout = &plan.layout[0];
        let words = layout.chunks * 16;
        let (_, pattern_indices) = &plan.target_patterns[0];

        body.push_str("        uint cand = 0u;\n");
        body.push_str(&format!(
            "        for (uint c = 0; c < {candidates}u; c++) {{\n            uint base = c * {words}u;\n"
        ));
        body.push_str(&sha1_block(0, "hashdata + base", layout.chunks, true));
        for &pattern_index in pattern_indices {
            let filter = patterns[pattern_index].pattern.filter.replace("h[", "h0[");
            body.push_str(&format!(
                "            if ({filter}) mask |= {}u;\n",
                1u32 << pattern_index
            ));
        }
        // Close the packet block opened by `sha1_block`.
        body.push_str("        }\n");
        body.push_str("            if (mask) { cand = c; break; }\n");
        body.push_str("        }\n");
        body.push_str(
            "        if (mask) {\n            result[0] = ts;\n            result[1] = mask;\n            result[2] = cand;\n            break;\n        }\n",
        );
        return body;
    }

    // Every key packet shares the same creation timestamp, which sits right
    // after the packet header (word 1 of that packet's hash data).
    for layout in &plan.layout {
        body.push_str(&format!("        data[{}] = ts;\n", layout.offset + 1));
    }

    for (index, (_, pattern_indices)) in plan.target_patterns.iter().enumerate() {
        let layout = &plan.layout[index];
        body.push_str(&sha1_block(
            index,
            &format!("data + {}", layout.offset),
            layout.chunks,
            false,
        ));
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
        "        if (mask) {\n            result[0] = ts;\n            result[1] = mask;\n            result[2] = 0u;\n            break;\n        }\n",
    );

    body
}

/// Build the OpenCL program for a plan.
#[cfg(feature = "opencl")]
fn build_program(
    device: Device,
    dimension: usize,
    plan: &SearchPlan,
    patterns: &[ActivePattern],
    future: bool,
    candidates: usize,
) -> anyhow::Result<(ProQue, Buffer<u32>)> {
    let injects = [
        format!("#define FUTURE_MODE ({})", if future { 1 } else { 0 }),
        format!("#define BATCHED ({})", if candidates > 1 { 1 } else { 0 }),
        format!(
            "#define TOTAL_WORDS ({})",
            plan.total_words.saturating_mul(candidates)
        ),
    ];

    let pro_que = ProQue::builder()
        .src(
            std::include_str!("shader.cl")
                .replace("#define __INJECTS__", &injects.join("\n"))
                .replace(
                    "// __TARGET_CHECKS__",
                    &generate_target_checks(plan, patterns, candidates),
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

    // A build without the `opencl` feature has no GPU backend at all.
    let cpu_mode = ARGS.cpu || !cfg!(feature = "opencl");
    if !cfg!(feature = "opencl") {
        info!("This build was compiled without OpenCL support; using the CPU");
    }

    // The CPU backend never opens an OpenCL runtime; only list devices or the
    // GPU backend do.
    #[cfg(feature = "opencl")]
    let device_list = if ARGS.list_device || !cpu_mode {
        Some(utils::DeviceList::new()?)
    } else {
        None
    };

    #[cfg(feature = "opencl")]
    if ARGS.list_device {
        let device_list = device_list
            .as_ref()
            .expect("the device list is built for --list-device");
        info!("Available OpenCL devices: \n");
        for (i, device) in device_list.iter().enumerate() {
            println!("Device #{i} - {device:?}");
        }
        return Ok(());
    }

    #[cfg(not(feature = "opencl"))]
    if ARGS.list_device {
        bail!("This build was compiled without OpenCL support, so there are no devices to list");
    }

    #[cfg(feature = "opencl")]
    let device = if cpu_mode {
        None
    } else {
        let device_list = device_list
            .as_ref()
            .expect("the device list is built without --cpu");
        Some(match ARGS.device {
            Some(i) => device_list[i].device,
            None => Device::first(Platform::default())?,
        })
    };

    #[cfg(feature = "opencl")]
    if let Some(device) = &device {
        info!("Using device: {}", device.name()?);
    }

    #[cfg(feature = "opencl")]
    let dimension = match (&device, ARGS.thread) {
        (_, Some(v)) => v,
        (Some(device), None) => match device.info(ocl::core::DeviceInfo::MaxWorkItemSizes)? {
            ocl::core::DeviceInfoResult::MaxWorkItemSizes(wgs) => {
                let dimension = usize::max(wgs[0] * wgs[1], 1048576);
                info!("Auto set thread: {dimension}");
                dimension
            }
            _ => unreachable!(),
        },
        (None, None) => 0,
    };

    #[cfg(feature = "opencl")]
    let iteration = ARGS.iteration;

    let cpu_threads = match ARGS.cpu_threads {
        Some(0) => bail!("--cpu-threads must be at least 1"),
        Some(threads) => threads,
        None => std::thread::available_parallelism()
            .map(|threads| threads.get())
            .unwrap_or(1),
    };
    if cpu_mode {
        info!("Using the CPU with {cpu_threads} thread(s)");
        if ARGS.thread.is_some() || ARGS.iteration != 512 {
            warn!("--thread and --iteration only apply to the GPU and are ignored with --cpu");
        }
        if ARGS.device.is_some() {
            warn!("--device is ignored with --cpu");
        }
    }

    // Determine the starting timestamp
    let start_timestamp = ARGS
        .start_timestamp
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

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
    if cpu_mode && ARGS.filter.is_some() {
        bail!("--filter is an OpenCL expression and cannot be evaluated on the CPU; use --pattern instead");
    }

    let mut rng = thread_rng();

    match ARGS.cipher_suite {
        CipherSuite::RSA2048 | CipherSuite::RSA3072 | CipherSuite::RSA4096 => {
            warn!("Generating RSA vanity keys is not recommended. Too slow!")
        }
        _ => (),
    };

    let mut vanity_key = match &ARGS.key_file {
        Some(path) => load_existing_key(path, &mut rng)?,
        None => VanitySecretKey::new(ARGS.cipher_suite, ARGS.user_id.clone(), &mut rng),
    };
    if ARGS.key_file.is_some() {
        if ARGS.user_id != "Dummy <dummy@example.com>" {
            warn!("--user-id is ignored with --key-file; the imported key keeps its user IDs");
        }
        warn!(
            "The imported key keeps its existing subkeys; use `gpg --edit-key` if you want to revoke or expire the ones you no longer use"
        );
    }

    // Set the initial timestamp for the key.
    // Ensure we use the full timestamp value, not truncated.
    let initial_timestamp = if start_timestamp > u32::MAX as i64 {
        warn!(
            "Timestamp {} is too large for u32, may cause unexpected behavior",
            start_timestamp
        );
        start_timestamp as u32
    } else {
        start_timestamp as u32
    };

    let appended_target = vanity_key.appended_target();
    let primary_created = appended_target.map(|_| vanity_key.primary_created_at());

    // A subkey cannot be created before its primary key (GnuPG refuses to make
    // one), so there is no room to search backwards when the key is brand new.
    let forward = ARGS.future_timestamp
        || matches!(primary_created, Some(primary) if initial_timestamp <= primary);
    if !ARGS.future_timestamp && ARGS.start_timestamp.is_some() {
        if let Some(primary) = primary_created {
            ensure!(
                initial_timestamp > primary,
                "The start timestamp ({}) is not after the primary key's creation time ({}); a subkey cannot be created earlier. Pass --future-timestamp or a later --start-timestamp",
                format_timestamp(initial_timestamp as u64),
                format_timestamp(primary as u64),
            );
        }
    }

    // An appended subkey cannot be created before its primary key, so the GPU
    // must not walk further back than that.
    let search_range = match primary_created {
        Some(primary) if !forward => {
            let room = u32::try_from(initial_timestamp as u64 - primary as u64)
                .unwrap_or(u32::MAX)
                .max(1);
            ARGS.max_time_range
                .map_or(room, |time_range| time_range.min(room))
                .max(1)
        }
        _ => ARGS.max_time_range.unwrap_or(0),
    };

    info!(
        "Starting search from {} and going {} in time{}",
        format_timestamp(initial_timestamp as u64),
        if forward { "forward" } else { "backward" },
        if ARGS.max_time_range.is_some() {
            format!(" (up to {} seconds)", ARGS.max_time_range.unwrap())
        } else {
            String::new()
        },
    );
    if forward && !ARGS.future_timestamp {
        if let Some(primary) = primary_created {
            info!(
                "The primary key was created at {}, so the new subkey is searched forwards in time",
                format_timestamp(primary as u64)
            );
        }
    }

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

    info!(
        "Using base timestamp: {} ({})",
        initial_timestamp,
        chrono::DateTime::from_timestamp(initial_timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );

    vanity_key.edit_timestamp(initial_timestamp, &mut rng)?;

    #[cfg(feature = "opencl")]
    let stride = if cpu_mode {
        CPU_ROUND_TIMESTAMPS
    } else {
        (dimension as u64).saturating_mul(iteration as u64)
    };
    #[cfg(not(feature = "opencl"))]
    let stride = CPU_ROUND_TIMESTAMPS;

    // A GPU launch searches this many timestamps per candidate. When the window
    // is short (young primary key), several fresh candidates are searched in the
    // same launch so the device still gets a full round of work. The CPU backend
    // always searches a single candidate per round.
    #[cfg(feature = "opencl")]
    let candidates_per_round = match appended_target {
        Some(_) if !cpu_mode => batch_size(search_range, stride),
        _ => 1,
    };
    #[cfg(not(feature = "opencl"))]
    let candidates_per_round = 1;

    let mut plan = build_plan(&active, &vanity_key)?;

    // Candidates of the current launch. Fresh mode regenerates one whole key per
    // round; append mode keeps the imported key and only replaces the new
    // subkey's key material.
    let mut candidates: Vec<VanitySecretKey> = match appended_target {
        Some(_) => (0..candidates_per_round)
            .map(|_| vanity_key.new_candidate(initial_timestamp, &mut rng))
            .collect::<anyhow::Result<_>>()?,
        None => vec![vanity_key],
    };
    let mut hashdata = prepare_batch_hashdata(&candidates, &plan)?;

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
    if candidates_per_round > 1 {
        info!(
            "The timestamp window is short, so {candidates_per_round} candidate subkeys are searched per GPU round"
        );
    }

    #[cfg(feature = "opencl")]
    let mut job_sender = None;
    #[cfg(feature = "opencl")]
    let mut result_receiver = None;
    #[cfg(feature = "opencl")]
    if !cpu_mode {
        let (pro_que, buffer_result) = build_program(
            device.expect("a device is selected without --cpu"),
            dimension,
            &plan,
            &active,
            forward,
            candidates_per_round,
        )?;
        let (tx_job, rx_job) = channel::<OpenClJob>();
        let (tx_result, rx_result) = channel::<Option<(u32, u32, u32)>>();
        thread::spawn(move || opencl_thread(pro_que, buffer_result, rx_job, tx_result));
        job_sender = Some(tx_job);
        result_receiver = Some(rx_result);
    }

    // Candidates one round evaluates per candidate key packet: the kernel stops
    // at `max_time_range` unless that is 0 ("unlimited").
    let bench_size = per_round_hashes(stride, search_range);
    let bar = bars.add(init_progress_bar(plan.estimate_hashes()));

    let mut hashed: u64 = 0;
    let mut start = Instant::now();

    loop {
        debug!("Run one search round");
        #[cfg(feature = "opencl")]
        let (next_candidates, vanity_result): (
            Vec<VanitySecretKey>,
            Option<(u32, u32, u32)>,
        ) = if cpu_mode {
            run_cpu_round(
                &hashdata,
                &plan,
                &active,
                &candidates,
                appended_target.is_some(),
                candidates_per_round,
                bench_size,
                forward,
                initial_timestamp,
                cpu_threads,
                &mut rng,
            )?
        } else {
            job_sender
                .as_ref()
                .expect("the OpenCL thread is running")
                .send(OpenClJob::Search {
                    hashdata: std::mem::take(&mut hashdata),
                    max_time_range: search_range,
                })?;
            let next = next_candidates(
                &candidates,
                appended_target.is_some(),
                candidates_per_round,
                initial_timestamp,
                &mut rng,
            )?;
            let result = result_receiver
                .as_ref()
                .expect("the OpenCL thread is running")
                .recv()?;
            (next, result)
        };
        #[cfg(not(feature = "opencl"))]
        let (next_candidates, vanity_result): (
            Vec<VanitySecretKey>,
            Option<(u32, u32, u32)>,
        ) = run_cpu_round(
            &hashdata,
            &plan,
            &active,
            &candidates,
            appended_target.is_some(),
            candidates_per_round,
            bench_size,
            forward,
            initial_timestamp,
            cpu_threads,
            &mut rng,
        )?;

        let work = bench_size * plan.work_per_nonce() * candidates_per_round as u64;
        hashed += work;
        bar.inc(work);

        let elapsed = start.elapsed().as_secs_f64();

        let mut matched_patterns: Vec<usize> = Vec::new();
        let mut matched_candidate = 0usize;
        if let Some((vanity_timestamp, mask, candidate)) = vanity_result {
            matched_candidate = candidate as usize;
            let key = &mut candidates[matched_candidate];
            key.edit_timestamp(vanity_timestamp, &mut rng)?;
            matched_patterns = verify_matches(key, &active, mask);
        }

        if !matched_patterns.is_empty() {
            let key = &mut candidates[matched_candidate];
            // Candidates are kept unprotected while searching; only the key
            // that is actually written out inherits the passphrase protection.
            key.protect_appended_subkey(&mut rng)?;
            key.log_state();

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
                let primary = hex::encode_upper(key.secret_key.fingerprint().as_bytes());
                // With an appended subkey the primary key is the same for every
                // result, so the new subkey's fingerprint has to name the file.
                let file_name = match key.appended_fingerprint() {
                    Some(subkey) => {
                        format!("{primary}-{}-sec.asc", hex::encode_upper(subkey.as_bytes()))
                    }
                    None => format!("{primary}-sec.asc"),
                };
                fs::write(
                    Path::new(output_dir).join(file_name),
                    key.to_armored_string()?,
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

                plan = build_plan(&active, key)?;
                #[cfg(feature = "opencl")]
                if let Some(tx_job) = &job_sender {
                    let (pro_que, buffer_result) = build_program(
                        device.expect("a device is selected without --cpu"),
                        dimension,
                        &plan,
                        &active,
                        forward,
                        candidates_per_round,
                    )?;
                    tx_job.send(OpenClJob::Reconfigure {
                        pro_que,
                        buffer_result,
                    })?;
                }
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

        candidates = next_candidates;
        hashdata = prepare_batch_hashdata(&candidates, &plan)?;
    }

    Ok(())
}

/// Load the existing key given by `--key-file` and append the vanity subkey.
fn load_existing_key(
    path: &str,
    rng: &mut (impl Rng + CryptoRng),
) -> anyhow::Result<VanitySecretKey> {
    let file =
        fs::File::open(path).with_context(|| format!("Cannot open --key-file \"{path}\""))?;
    let key = load_secret_key(file, ARGS.key_id.as_deref())
        .with_context(|| format!("Cannot read a secret key from \"{path}\""))?;
    let passphrase = resolve_passphrase(&key)?;

    let vanity_key = VanitySecretKey::from_existing(key, ARGS.cipher_suite, passphrase, rng)?;
    info!(
        "Extending the existing key {} (created at {})",
        hex::encode_upper(vanity_key.secret_key.fingerprint().as_bytes()),
        vanity_key
            .secret_key
            .created_at()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    );
    Ok(vanity_key)
}

/// Work out the passphrase for the key given by `--key-file`.
fn resolve_passphrase(key: &pgp::SignedSecretKey) -> anyhow::Result<String> {
    let protected = matches!(key.primary_key.secret_params(), SecretParams::Encrypted(_));

    let given = match (&ARGS.passphrase, &ARGS.passphrase_file) {
        (Some(passphrase), _) => Some(passphrase.clone()),
        (None, Some(path)) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Cannot read --passphrase-file \"{path}\""))?;
            Some(content.trim_end_matches(&['\r', '\n'][..]).to_string())
        }
        (None, None) => None,
    };

    match (protected, given) {
        (true, None) => bail!(
            "The key given by --key-file is passphrase-protected; pass --passphrase or --passphrase-file"
        ),
        (false, Some(_)) => {
            warn!("The key given by --key-file is not passphrase-protected; ignoring the passphrase");
            Ok(String::new())
        }
        (_, Some(passphrase)) => Ok(passphrase),
        (false, None) => Ok(String::new()),
    }
}

fn format_timestamp(timestamp: u64) -> String {
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| timestamp.to_string())
}

/// Number of candidate timestamps the kernel evaluates in one round.
///
/// The kernel iterates `iteration` times over `dimension` threads and breaks
/// once `offset > max_time_range`; a range of 0 means "no limit".
fn per_round_hashes(stride: u64, max_time_range: u32) -> u64 {
    match max_time_range {
        0 => stride,
        range => (u64::from(range) + 1).min(stride),
    }
}

/// Number of candidate key packets to search in one GPU launch.
///
/// A launch covers at most `stride` timestamps per packet. When the timestamp
/// window is shorter than that (a recently created primary key), searching
/// several fresh candidates in the same launch keeps the device busy instead of
/// paying the launch cost for a tiny amount of work.
#[cfg(feature = "opencl")]
fn batch_size(search_range: u32, stride: u64) -> usize {
    const MAX_BATCH: u64 = 512;
    if search_range == 0 {
        return 1;
    }
    let window = u64::from(search_range) + 1;
    stride
        .saturating_add(window - 1)
        .checked_div(window)
        .unwrap_or(1)
        .clamp(1, MAX_BATCH) as usize
}

/// Concatenate the hash data of every candidate of one launch.
fn prepare_batch_hashdata(
    candidates: &[VanitySecretKey],
    plan: &SearchPlan,
) -> anyhow::Result<Vec<u32>> {
    let mut all = Vec::with_capacity(plan.total_words * candidates.len());
    for key in candidates {
        all.extend(prepare_hashdata(key, plan)?);
    }
    Ok(all)
}

/// Candidate keys for the next round.
///
/// Append mode keeps the imported key and only gives the new subkey fresh key
/// material; fresh-key mode generates a whole new key.
fn next_candidates(
    candidates: &[VanitySecretKey],
    appended: bool,
    count: usize,
    timestamp: u32,
    rng: &mut (impl Rng + CryptoRng),
) -> anyhow::Result<Vec<VanitySecretKey>> {
    if appended {
        let base = &candidates[0];
        (0..count)
            .map(|_| base.new_candidate(timestamp, &mut *rng))
            .collect()
    } else {
        let mut key = VanitySecretKey::new(ARGS.cipher_suite, ARGS.user_id.clone(), &mut *rng);
        // Set the same initial timestamp for consistency.
        key.edit_timestamp(timestamp, &mut *rng)?;
        Ok(vec![key])
    }
}

/// One CPU search round: scan the timestamp window and prepare the next set of
/// candidate keys.
#[allow(clippy::too_many_arguments)]
fn run_cpu_round(
    hashdata: &[u32],
    plan: &SearchPlan,
    active: &[ActivePattern],
    candidates: &[VanitySecretKey],
    appended: bool,
    count: usize,
    bench_size: u64,
    forward: bool,
    initial_timestamp: u32,
    cpu_threads: usize,
    rng: &mut (impl Rng + CryptoRng),
) -> anyhow::Result<(Vec<VanitySecretKey>, Option<(u32, u32, u32)>)> {
    let result = cpu_search(
        hashdata,
        plan,
        active,
        bench_size,
        forward,
        initial_timestamp,
        cpu_threads,
    );
    let next = next_candidates(candidates, appended, count, initial_timestamp, rng)?;
    Ok((next, result))
}

/// SHA-1 over the already padded big-endian words from `manually_prepare_sha1`.
fn sha1_digest(words: &[u32]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for block in words.chunks_exact(16) {
        // Rolling 16-word message schedule; the round groups use fixed
        // functions so the compiler can unroll them.
        let mut w = [0u32; 16];
        w.copy_from_slice(block);

        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);

        for &word in &w {
            let f = (b & c) | (!b & d);
            round(&mut a, &mut b, &mut c, &mut d, &mut e, 0x5A827999, f, word);
        }
        for j in 16..20 {
            w[j & 15] =
                (w[(j + 13) & 15] ^ w[(j + 8) & 15] ^ w[(j + 2) & 15] ^ w[j & 15]).rotate_left(1);
            let f = (b & c) | (!b & d);
            round(
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut e,
                0x5A827999,
                f,
                w[j & 15],
            );
        }
        for j in 20..40 {
            w[j & 15] =
                (w[(j + 13) & 15] ^ w[(j + 8) & 15] ^ w[(j + 2) & 15] ^ w[j & 15]).rotate_left(1);
            let f = b ^ c ^ d;
            round(
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut e,
                0x6ED9EBA1,
                f,
                w[j & 15],
            );
        }
        for j in 40..60 {
            w[j & 15] =
                (w[(j + 13) & 15] ^ w[(j + 8) & 15] ^ w[(j + 2) & 15] ^ w[j & 15]).rotate_left(1);
            let f = (b & c) | (b & d) | (c & d);
            round(
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut e,
                0x8F1BBCDC,
                f,
                w[j & 15],
            );
        }
        for j in 60..80 {
            w[j & 15] =
                (w[(j + 13) & 15] ^ w[(j + 8) & 15] ^ w[(j + 2) & 15] ^ w[j & 15]).rotate_left(1);
            let f = b ^ c ^ d;
            round(
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut e,
                0xCA62C1D6,
                f,
                w[j & 15],
            );
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// One SHA-1 compression round.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, e: &mut u32, k: u32, f: u32, w: u32) {
    let t = a
        .rotate_left(5)
        .wrapping_add(f)
        .wrapping_add(*e)
        .wrapping_add(k)
        .wrapping_add(w);
    *e = *d;
    *d = *c;
    *c = b.rotate_left(30);
    *b = *a;
    *a = t;
}

/// Search the current candidates on the CPU.
///
/// Scans `window` timestamps from `nonce`, in the same direction and with the
/// same numbering as the OpenCL kernel, and returns
/// `(timestamp, pattern mask, candidate index)` for the first match.
fn cpu_search(
    hashdata: &[u32],
    plan: &SearchPlan,
    active: &[ActivePattern],
    window: u64,
    forward: bool,
    nonce: u32,
    threads: usize,
) -> Option<(u32, u32, u32)> {
    let candidates = hashdata.len() / plan.total_words;
    let found = AtomicBool::new(false);
    let result: Mutex<Option<(u32, u32, u32)>> = Mutex::new(None);

    let scan = |range: std::ops::Range<u64>| {
        // Each thread keeps its own copy so the timestamp word can be replaced
        // without synchronisation.
        let mut data = hashdata.to_vec();

        for offset in range {
            if found.load(Ordering::Relaxed) {
                return;
            }

            // Same overflow behaviour as the kernel.
            let timestamp = offset as u32;
            let ts = if forward {
                match nonce.checked_add(timestamp) {
                    Some(ts) => ts,
                    None => return,
                }
            } else {
                match nonce.checked_sub(timestamp) {
                    Some(ts) => ts,
                    None => return,
                }
            };

            let mut mask = 0u32;
            for candidate in 0..candidates {
                let base = candidate * plan.total_words;
                for (index, (_, pattern_indices)) in plan.target_patterns.iter().enumerate() {
                    let layout = &plan.layout[index];
                    let start = base + layout.offset;
                    // Word 1 of the packet is its creation time.
                    data[start + 1] = ts;
                    let digest = sha1_digest(&data[start..start + layout.chunks * 16]);
                    for &pattern_index in pattern_indices {
                        if active[pattern_index].pattern.is_match(&digest) {
                            mask |= 1u32 << pattern_index;
                        }
                    }
                }

                if mask != 0 {
                    let mut slot = result.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some((ts, mask, candidate as u32));
                    }
                    found.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
    };

    let chunk = window.div_ceil(threads as u64).max(1);
    thread::scope(|scope| {
        for thread_index in 0..threads {
            let start = thread_index as u64 * chunk;
            if start >= window {
                break;
            }
            let end = (start + chunk).min(window);
            let scan = &scan;
            scope.spawn(move || scan(start..end));
        }
    });

    result.into_inner().unwrap()
}

/// Work for the OpenCL thread.
#[cfg(feature = "opencl")]
enum OpenClJob {
    /// Use a new program (the searched patterns changed).
    Reconfigure {
        pro_que: ProQue,
        buffer_result: Buffer<u32>,
    },
    Search {
        hashdata: Vec<u32>,
        /// Only timestamps within this range (relative to the nonce) are
        /// tried; 0 means unlimited.
        max_time_range: u32,
    },
}

#[cfg(feature = "opencl")]
fn opencl_thread(
    mut pro_que: ProQue,
    mut buffer_result: Buffer<u32>,
    rx_job: Receiver<OpenClJob>,
    tx_result: Sender<Option<(u32, u32, u32)>>,
) {
    let mut vec = vec![0; RESULT_WORDS];
    debug!("OpenCL thread ready");

    while let Ok(job) = rx_job.recv() {
        let (hashdata, max_time_range) = match job {
            OpenClJob::Reconfigure {
                pro_que: new_pro_que,
                buffer_result: new_buffer_result,
            } => {
                pro_que = new_pro_que;
                buffer_result = new_buffer_result;
                continue;
            }
            OpenClJob::Search {
                hashdata,
                max_time_range,
            } => (hashdata, max_time_range),
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
            .arg(max_time_range)
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
                Some((vec[0], vec[1], vec[2]))
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

    #[test]
    fn per_round_hash_count_matches_the_kernel_loop() {
        // 0 means "unlimited": the whole stride is evaluated.
        assert_eq!(per_round_hashes(1_000, 0), 1_000);
        // A range of R lets offsets 0..=R through.
        assert_eq!(per_round_hashes(1_000, 1), 2);
        assert_eq!(per_round_hashes(1_000, 100), 101);
        // The range can never make the kernel do more than its stride.
        assert_eq!(per_round_hashes(1_000, 999), 1_000);
        assert_eq!(per_round_hashes(1_000, u32::MAX), 1_000);
    }

    #[test]
    #[cfg(feature = "opencl")]
    fn short_windows_search_several_candidates_per_round() {
        let stride = 536_870_912;
        // Unlimited window: one candidate is enough to fill the launch.
        assert_eq!(batch_size(0, stride), 1);
        // A two-year window (~63M seconds) fits a couple of times.
        assert_eq!(batch_size(63_000_000, stride), 9);
        // ~24M seconds: 23 candidates.
        assert_eq!(batch_size(24_000_000, stride), 23);
        // Tiny windows are capped so the CPU still keeps up.
        assert_eq!(batch_size(1_000_000, stride), 512);
        assert_eq!(batch_size(10_000, stride), 512);
        // A window longer than the launch needs no batching.
        assert_eq!(batch_size(500_000_000, stride), 2);
        assert_eq!(batch_size(u32::MAX, stride), 1);
    }

    #[test]
    fn cpu_sha1_matches_known_vectors() {
        assert_eq!(
            hex::encode(sha1_digest(&manually_prepare_sha1(b"abc".to_vec()))),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(sha1_digest(&manually_prepare_sha1(Vec::new()))),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn cpu_sha1_matches_the_crypto_crate() {
        let key = key();
        let hashdata = key.hashdata_for(KeyTarget::Primary);
        let digest = sha1_digest(&manually_prepare_sha1(hashdata.clone()));
        let expected = pgp::crypto::hash::HashAlgorithm::SHA1
            .digest(&hashdata)
            .unwrap();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn cpu_search_finds_the_matching_timestamp() {
        let key = key();
        let fingerprint = key.secret_key.fingerprint();
        // Match the exact fingerprint of the key at its creation time.
        let pattern: HashPattern = hex::encode_upper(fingerprint.as_bytes()).parse().unwrap();
        let active = vec![ActivePattern {
            pattern,
            targets: vec![KeyTarget::Primary],
        }];
        let plan = build_plan(&active, &key).unwrap();
        let hashdata = prepare_hashdata(&key, &plan).unwrap();
        let created_at = key.secret_key.created_at().timestamp() as u32;

        // The timestamp is at offset 0 of the window.
        assert_eq!(
            cpu_search(&hashdata, &plan, &active, 1, true, created_at, 2),
            Some((created_at, 1, 0))
        );
        // Backward search: five seconds after the creation time, the match is
        // at offset 5.
        assert_eq!(
            cpu_search(&hashdata, &plan, &active, 6, false, created_at + 5, 3),
            Some((created_at, 1, 0))
        );
        // Forward search: five seconds before, also at offset 5.
        assert_eq!(
            cpu_search(&hashdata, &plan, &active, 6, true, created_at - 5, 3),
            Some((created_at, 1, 0))
        );
        // A window that does not contain the creation time has no match.
        assert_eq!(
            cpu_search(&hashdata, &plan, &active, 1, true, created_at + 1, 2),
            None
        );
    }
}
