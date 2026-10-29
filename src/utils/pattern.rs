use std::{collections::HashMap, fmt, str::FromStr};

use anyhow::{bail, Result};

use super::KeyTarget;

/// Number of hex digits (nibbles) in a fingerprint.
const FINGERPRINT_NIBBLES: usize = 40;

/// Which key packet(s) a pattern is matched against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelector {
    /// Every key packet of the generated key.
    All,
    /// One or more explicitly named key packets.
    Targets(Vec<KeyTarget>),
}

impl TargetSelector {
    /// Parse `primary`, `sign`, `encrypt`, `all`, or a `+`-joined list of them.
    pub fn parse(s: &str) -> Result<Self> {
        let mut all = false;
        let mut targets: Vec<KeyTarget> = Vec::new();

        for part in s.split('+') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.eq_ignore_ascii_case("all") {
                all = true;
                continue;
            }
            let target: KeyTarget = part.parse()?;
            if !targets.contains(&target) {
                targets.push(target);
            }
        }

        if all {
            Ok(Self::All)
        } else if targets.is_empty() {
            bail!("Empty key target in \"{s}\"");
        } else {
            Ok(Self::Targets(targets))
        }
    }

    /// Merge the values of a repeatable command line option into one selector.
    pub fn merge(values: &[String]) -> Result<Option<Self>> {
        if values.is_empty() {
            return Ok(None);
        }

        let mut all = false;
        let mut targets: Vec<KeyTarget> = Vec::new();
        for value in values {
            match Self::parse(value)? {
                Self::All => all = true,
                Self::Targets(list) => {
                    for target in list {
                        if !targets.contains(&target) {
                            targets.push(target);
                        }
                    }
                }
            }
        }

        Ok(Some(if all {
            Self::All
        } else {
            Self::Targets(targets)
        }))
    }

    /// Expand the selector to the packets that actually exist, in a stable order.
    pub fn expand(&self, available: &[KeyTarget]) -> Vec<KeyTarget> {
        match self {
            Self::All => available.to_vec(),
            Self::Targets(list) => available
                .iter()
                .copied()
                .filter(|target| list.contains(target))
                .collect(),
        }
    }
}

/// A constraint on a single nibble of the fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleConstraint {
    /// Anything goes.
    Any,
    /// Must be exactly this hex digit.
    Fixed(u8),
    /// Must not be this hex digit.
    NotFixed(u8),
    /// Must be a decimal digit (0-9).
    Decimal,
    /// Must not be a decimal digit.
    NotDecimal,
    /// Must equal the nibble at this position (same-letter matching).
    SameAs(usize),
    /// Must differ from the nibble at this position.
    DifferentFrom(usize),
}

/// A single fingerprint pattern.
///
/// The pattern is compiled once into a list of per-nibble constraints, which is
/// then used both to generate the OpenCL filter expression and to re-check the
/// fingerprint on the CPU, so both sides can never disagree.
#[derive(Debug, Clone)]
pub struct HashPattern {
    /// The original text given on the command line.
    pub source: String,
    /// Key packets named with a `primary:` / `sign:` / `all:` prefix, if any.
    pub selector: Option<TargetSelector>,
    /// Constraints for the nibbles that are not free.
    pub constraints: Vec<(usize, NibbleConstraint)>,
    /// OpenCL expression over `uint h[5]` implementing the constraints.
    pub filter: String,
    /// Reciprocal of the probability that a random fingerprint matches.
    pub possibility: f64,
    /// True for a raw `--filter` expression, which the CPU cannot re-check.
    pub raw: bool,
}

impl HashPattern {
    /// Wrap a raw OpenCL filter as a pattern.
    ///
    /// It has no constraints, so it always passes the CPU re-check; the filter
    /// expression itself decides whether the fingerprint matches.
    pub fn raw(filter: String) -> Self {
        Self {
            source: String::from("--filter"),
            selector: None,
            constraints: Vec::new(),
            filter,
            possibility: f64::INFINITY,
            raw: true,
        }
    }

    /// Check a 20-byte fingerprint against this pattern.
    pub fn is_match(&self, fingerprint: &[u8]) -> bool {
        if fingerprint.len() != FINGERPRINT_NIBBLES / 2 {
            return false;
        }

        let nibble = |pos: usize| -> u8 {
            let byte = fingerprint[pos / 2];
            if pos.is_multiple_of(2) {
                byte >> 4
            } else {
                byte & 0xF
            }
        };

        self.constraints
            .iter()
            .all(|&(pos, constraint)| match constraint {
                NibbleConstraint::Any => true,
                NibbleConstraint::Fixed(v) => nibble(pos) == v,
                NibbleConstraint::NotFixed(v) => nibble(pos) != v,
                NibbleConstraint::Decimal => nibble(pos) <= 9,
                NibbleConstraint::NotDecimal => nibble(pos) > 9,
                NibbleConstraint::SameAs(anchor) => nibble(pos) == nibble(anchor),
                NibbleConstraint::DifferentFrom(anchor) => nibble(pos) != nibble(anchor),
            })
    }

    /// `(word index, bit shift)` of a nibble in the big-endian hash output.
    fn nibble_location(pos: usize) -> (usize, u32) {
        (pos / 8, (7 - pos % 8) as u32 * 4)
    }

    fn build_filter(constraints: &[(usize, NibbleConstraint)]) -> String {
        let mut parts: Vec<String> = Vec::new();

        // Exact digits are grouped per word into a single mask comparison.
        let mut masks = [0u32; 5];
        let mut values = [0u32; 5];
        for &(pos, constraint) in constraints {
            if let NibbleConstraint::Fixed(v) = constraint {
                let (word, shift) = Self::nibble_location(pos);
                masks[word] |= 0xF << shift;
                values[word] |= (v as u32) << shift;
            }
        }
        for word in 0..5 {
            if masks[word] != 0 {
                parts.push(format!(
                    "(h[{word}] & 0x{:X}) == 0x{:X}",
                    masks[word], values[word]
                ));
            }
        }

        for &(pos, constraint) in constraints {
            let (word, shift) = Self::nibble_location(pos);
            let part = match constraint {
                NibbleConstraint::Any | NibbleConstraint::Fixed(_) => continue,
                NibbleConstraint::NotFixed(v) => {
                    format!("((h[{word}] >> {shift}) & 0xF) != 0x{v:X}")
                }
                NibbleConstraint::Decimal => {
                    format!("((h[{word}] >> {shift}) & 0xF) <= 0x9")
                }
                NibbleConstraint::NotDecimal => {
                    format!("((h[{word}] >> {shift}) & 0xF) > 0x9")
                }
                NibbleConstraint::SameAs(anchor) => {
                    let (anchor_word, anchor_shift) = Self::nibble_location(anchor);
                    format!(
                        "((h[{anchor_word}] >> {anchor_shift}) & 0xF) == ((h[{word}] >> {shift}) & 0xF)"
                    )
                }
                NibbleConstraint::DifferentFrom(anchor) => {
                    let (anchor_word, anchor_shift) = Self::nibble_location(anchor);
                    format!(
                        "((h[{anchor_word}] >> {anchor_shift}) & 0xF) != ((h[{word}] >> {shift}) & 0xF)"
                    )
                }
            };
            parts.push(part);
        }

        if parts.is_empty() {
            String::from("true")
        } else {
            parts.join(" && ")
        }
    }
}

impl fmt::Display for HashPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

/// Split an optional `target:` / `target=` prefix off a pattern.
fn split_target_prefix(s: &str) -> Result<(Option<TargetSelector>, &str)> {
    for sep in [':', '='] {
        if let Some((head, rest)) = s.split_once(sep) {
            let head = head.trim();
            // Only treat it as a target prefix when the head looks like a name;
            // anything else is part of the pattern (and is ignored by the parser).
            if !head.is_empty()
                && head
                    .chars()
                    .all(|c| c.is_ascii_alphabetic() || c == '+' || c == '-' || c.is_whitespace())
            {
                return Ok((Some(TargetSelector::parse(head)?), rest));
            }
        }
    }
    Ok((None, s))
}

impl FromStr for HashPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let source = s.trim().to_string();
        let (selector, body) = split_target_prefix(&source)?;

        let cleaned: String = body
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();

        let anchored_start = cleaned.starts_with('^');
        let anchored_end = cleaned.ends_with('$');
        let mut inner = cleaned.as_str();
        if anchored_start {
            inner = &inner[1..];
        }
        if anchored_end && !inner.is_empty() {
            inner = &inner[..inner.len() - 1];
        }

        // '!' negates the character that follows it.
        let mut tokens: Vec<(char, bool)> = Vec::new();
        let mut negate = false;
        for c in inner.chars() {
            if c == '!' {
                negate = !negate;
                continue;
            }
            tokens.push((c, negate));
            negate = false;
        }

        if tokens.len() > FINGERPRINT_NIBBLES {
            bail!(
                "Invalid pattern \"{source}\": {} hex digits given, but a fingerprint only has {FINGERPRINT_NIBBLES}",
                tokens.len()
            );
        }

        // Default (and '$') matches at the end of the fingerprint, '^' at the beginning.
        let offset = if anchored_start && anchored_end {
            if tokens.len() != FINGERPRINT_NIBBLES {
                bail!(
                    "Invalid pattern \"{source}\": a pattern anchored with both '^' and '$' must be exactly {FINGERPRINT_NIBBLES} hex digits long"
                );
            }
            0
        } else if anchored_start {
            0
        } else {
            FINGERPRINT_NIBBLES - tokens.len()
        };

        // The first non-negated occurrence of a wildcard letter defines its value.
        let mut wildcard_anchor: HashMap<char, usize> = HashMap::new();
        for (i, &(c, negated)) in tokens.iter().enumerate() {
            if ('G'..='Z').contains(&c) && !negated {
                wildcard_anchor.entry(c).or_insert(offset + i);
            }
        }
        for &(c, negated) in &tokens {
            if ('G'..='Z').contains(&c) && negated && !wildcard_anchor.contains_key(&c) {
                bail!(
                    "Invalid pattern \"{source}\": wildcard '{c}' is only used negated; write it once without '!' to give it a value"
                );
            }
        }

        let mut constraints: Vec<(usize, NibbleConstraint)> = Vec::new();
        let mut possibility: f64 = 1.0;
        for (i, &(c, negated)) in tokens.iter().enumerate() {
            let pos = offset + i;
            let constraint = match c {
                '0'..='9' | 'A'..='F' => {
                    let value = c.to_digit(16).unwrap() as u8;
                    if negated {
                        NibbleConstraint::NotFixed(value)
                    } else {
                        NibbleConstraint::Fixed(value)
                    }
                }
                'G'..='Z' => {
                    let anchor = wildcard_anchor[&c];
                    if pos == anchor {
                        NibbleConstraint::Any
                    } else if negated {
                        NibbleConstraint::DifferentFrom(anchor)
                    } else {
                        NibbleConstraint::SameAs(anchor)
                    }
                }
                '#' => {
                    if negated {
                        NibbleConstraint::NotDecimal
                    } else {
                        NibbleConstraint::Decimal
                    }
                }
                // '*', '?' and any other character match anything.
                _ => NibbleConstraint::Any,
            };

            possibility *= match constraint {
                NibbleConstraint::Any => 1.0,
                NibbleConstraint::Fixed(_) => 16.0,
                NibbleConstraint::NotFixed(_) => 16.0 / 15.0,
                NibbleConstraint::Decimal => 16.0 / 10.0,
                NibbleConstraint::NotDecimal => 16.0 / 6.0,
                NibbleConstraint::SameAs(_) => 16.0,
                NibbleConstraint::DifferentFrom(_) => 16.0 / 15.0,
            };

            if constraint != NibbleConstraint::Any {
                constraints.push((pos, constraint));
            }
        }

        Ok(Self {
            source,
            selector,
            filter: Self::build_filter(&constraints),
            constraints,
            possibility,
            raw: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, fingerprint: &str) -> bool {
        let pattern: HashPattern = pattern.parse().unwrap();
        pattern.is_match(&hex::decode(fingerprint).unwrap())
    }

    /// A 40-digit fingerprint ending with `suffix`.
    fn ending(suffix: &str) -> String {
        format!("{}{suffix}", "0".repeat(FINGERPRINT_NIBBLES - suffix.len()))
    }

    /// A 40-digit fingerprint starting with `prefix`.
    fn starting(prefix: &str) -> String {
        format!("{prefix}{}", "0".repeat(FINGERPRINT_NIBBLES - prefix.len()))
    }

    #[test]
    fn fixed_digits_are_right_aligned_by_default() {
        assert!(matches("7777", &ending("77777777")));
        assert!(!matches("7777", &ending("77777770")));
        // A fingerprint that only starts with the pattern does not match.
        assert!(!matches(
            "7777",
            &starting("77770123456789ABCDEF0123456789ABCDEF")
        ));
    }

    #[test]
    fn wildcards_must_be_equal() {
        // G..Z are the same-letter wildcards, so GGGG means four equal digits.
        assert!(matches("GGGG", &ending("AAAAAAAA")));
        assert!(!matches("GGGG", &ending("AAAABAAA")));
        // Different letters are independent.
        assert!(matches("GHGH", &ending("ABAB")));
        assert!(!matches("GHGH", &ending("ABBA")));
    }

    #[test]
    fn any_and_decimal_digits() {
        assert!(matches("**77", &ending("1277")));
        assert!(matches("##", &ending("0077")));
        assert!(!matches("##", &ending("00AA")));
        assert!(matches("##!A", &ending("23B")));
        assert!(!matches("##!A", &ending("23A")));
    }

    #[test]
    fn negated_digits_and_wildcards() {
        assert!(matches("!7", &ending("8")));
        assert!(!matches("!7", &ending("7")));
        // G!G: two different digits.
        assert!(matches("G!G", &ending("12")));
        assert!(!matches("G!G", &ending("11")));
    }

    #[test]
    fn anchors_select_the_position() {
        assert!(matches("^7777", &starting("7777")));
        assert!(!matches("^7777", &ending("7777")));
        assert!(matches("7777$", &ending("7777")));
        let full = "0123456789ABCDEF0123456789ABCDEF01234567";
        assert!(matches(&format!("^{full}"), full));
    }

    #[test]
    fn possibility_is_the_reciprocal_probability() {
        assert_eq!(
            "7777".parse::<HashPattern>().unwrap().possibility,
            16f64.powi(4)
        );
        assert_eq!(
            "GGGG".parse::<HashPattern>().unwrap().possibility,
            16f64.powi(3)
        );
        assert_eq!(
            "GHGH".parse::<HashPattern>().unwrap().possibility,
            16f64.powi(2)
        );
        assert!((("##".parse::<HashPattern>().unwrap().possibility) - 2.56).abs() < 1e-9);
    }

    #[test]
    fn filter_only_contains_our_own_constraints() {
        let pattern: HashPattern = "GG77".parse().unwrap();
        assert!(pattern.filter.contains("h[4]"));
        assert!(!pattern.filter.is_empty());
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!("01234567890123456789012345678901234567890"
            .parse::<HashPattern>()
            .is_err());
        // Anchored at both ends but not 40 digits long.
        assert!("^ABCD$".parse::<HashPattern>().is_err());
        // Wildcard that is never given a value.
        assert!("!G".parse::<HashPattern>().is_err());
        assert!("sign:ABCD".parse::<HashPattern>().is_ok());
        assert!("nonsense:ABCD".parse::<HashPattern>().is_err());
    }

    #[test]
    fn target_prefix_is_parsed() {
        let pattern: HashPattern = "sign:ABCD".parse().unwrap();
        assert_eq!(
            pattern.selector,
            Some(TargetSelector::Targets(vec![KeyTarget::Sign]))
        );

        let pattern: HashPattern = "primary+sign:ABCD".parse().unwrap();
        assert_eq!(
            pattern.selector,
            Some(TargetSelector::Targets(vec![
                KeyTarget::Primary,
                KeyTarget::Sign
            ]))
        );

        let pattern: HashPattern = "all:ABCD".parse().unwrap();
        assert_eq!(pattern.selector, Some(TargetSelector::All));

        // Without a prefix the pattern belongs to the default selector.
        let pattern: HashPattern = "ABCD".parse().unwrap();
        assert_eq!(pattern.selector, None);
    }

    #[test]
    fn selectors_expand_to_available_packets() {
        let available = [KeyTarget::Primary, KeyTarget::Sign, KeyTarget::Encrypt];
        assert_eq!(
            TargetSelector::parse("all").unwrap().expand(&available),
            available
        );
        assert_eq!(
            TargetSelector::parse("encrypt+primary")
                .unwrap()
                .expand(&available),
            vec![KeyTarget::Primary, KeyTarget::Encrypt]
        );
        // Merging repeatable options keeps one entry per packet.
        assert_eq!(
            TargetSelector::merge(&["primary".to_string(), "primary+sign".to_string()])
                .unwrap()
                .unwrap(),
            TargetSelector::Targets(vec![KeyTarget::Primary, KeyTarget::Sign])
        );
    }
}
