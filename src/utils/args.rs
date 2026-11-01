use anyhow::bail;
use clap::{Parser, ValueEnum};
use pgp::{composed::KeyType, crypto::ecc_curve::ECCCurve};
use std::str::FromStr;
use std::sync::LazyLock;

pub static ARGS: LazyLock<Args> = LazyLock::new(if cfg!(debug_assertions) {
    Args::default
} else {
    Args::parse
});

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Cipher suite of the vanity key
    /// ed25519, ecdsa-****, rsa****       => Primary key
    /// cv25519,  ecdh-****                => Subkey
    /// ed25519-sign, ecdsa-****-sign      => Signing subkey
    /// Use gpg CLI for further editing of the key.
    #[arg(short, long, default_value_t, value_enum, verbatim_doc_comment)]
    pub cipher_suite: CipherSuite,

    /// OpenPGP compatible user ID
    #[arg(short, long, default_value_t = String::from("Dummy <dummy@example.com>"))]
    pub user_id: String,

    /// A pattern less than 40 chars for matching fingerprints
    /// Can be given multiple times (or comma-separated).
    /// > Format:
    /// * 0-9A-F are fixed
    /// * G-Z are wildcards, the same letter must be the same digit (e.g. GGGG)
    /// * '#' matches a decimal digit (0-9), '*' or '?' match anything
    /// * '!' negates what follows (e.g. !7 is not 7, G!G means two different digits)
    /// * '^' anchors at the start of the fingerprint, the default (or '$') at the end
    /// * Other chars will be ignored, case insensitive
    /// > Target:
    /// * Prefix a pattern with primary:, sign:, encrypt: or all: (combine with '+')
    ///   to match it against those key packets only
    /// * Without a prefix, the packets given by --algorithm are used
    /// > Example:
    /// * 11XXXX** may output a fingerprint ends with 11222234 or 11AAAABF
    /// * 11XXYYZZ may output a fingerprint ends with 11223344 or 11AABBCC
    /// * ^ABCD starts with ABCD
    /// * sign:#### makes the signing subkey end with 4 decimal digits
    #[arg(short, long, value_delimiter = ',', verbatim_doc_comment)]
    pub pattern: Vec<String>,

    /// Key packet(s) the patterns are matched against
    /// primary, encrypt, sign, or all. Can be given multiple times
    /// (or comma-separated, or joined with '+').
    /// Defaults to the packet selected by --cipher-suite.
    #[arg(short = 'a', long, value_delimiter = ',', verbatim_doc_comment)]
    pub algorithm: Vec<String>,

    /// OpenCL kernel function for uint h[5] for matching fingerprints
    /// Ignore the pattern and no estimate is given if this has been set
    /// > Example:
    /// * (h[4] & 0xFFFF)     == 0x1234     outputs a fingerprint ends with 1234
    /// * (h[0] & 0xFFFF0000) == 0xABCD0000 outputs a fingerprint starts with ABCD
    #[arg(short, long, verbatim_doc_comment)]
    pub filter: Option<String>,

    /// The dir where the vanity keys are saved
    #[arg(short, long)]
    pub output: Option<String>,

    /// Device ID to use
    #[arg(short, long)]
    pub device: Option<usize>,

    /// Adjust it to maximum your device's usage
    #[arg(short, long)]
    pub thread: Option<usize>,

    /// Adjust it to maximum your device's usage
    #[arg(short, long, default_value_t = 1 << 9)]
    pub iteration: usize,

    /// Exit after a specified time in seconds
    #[arg(long)]
    pub timeout: Option<f64>,

    /// Exit after getting a vanity key (any pattern matching once)
    #[arg(long, default_value_t = false, conflicts_with = "shot_all")]
    pub oneshot: bool,

    /// Keep searching until every pattern has matched at least once
    #[arg(long, default_value_t = false)]
    pub shot_all: bool,

    /// Don't print progress
    #[arg(long, default_value_t = false)]
    pub no_progress: bool,

    /// Don't print armored secret key
    #[arg(long, default_value_t = false)]
    pub no_secret_key_logging: bool,

    /// Show available OpenCL devices then exit
    #[arg(long, default_value_t = false)]
    pub list_device: bool,

    /// Generate keys with future timestamps instead of past timestamps
    /// When true: search from start_timestamp forward in time (start_timestamp + 0 to max_time_range)
    /// When false: search from start_timestamp backward in time (start_timestamp - max_time_range to start_timestamp - 0)
    #[arg(long, default_value_t = false, verbatim_doc_comment)]
    pub future_timestamp: bool,

    /// Custom timestamp to start searching from (Unix timestamp)
    /// This is the base time point from which the search begins
    /// If not specified, uses current time as the starting point
    /// Example: 1640995200 (Jan 1, 2022 00:00:00 UTC)
    #[arg(long, verbatim_doc_comment)]
    pub start_timestamp: Option<i64>,

    /// Maximum time range to search in seconds
    /// future_timestamp =  true: search from start_timestamp to (start_timestamp + max_time_range)
    /// future_timestamp = false: search from (start_timestamp - max_time_range) to start_timestamp
    #[arg(long, verbatim_doc_comment)]
    pub max_time_range: Option<u32>,

    /// Add a vanity subkey to this existing secret key instead of generating a new one
    /// Accepts an exported secret key (ASCII-armored or binary), for example:
    /// `gpg --export-secret-keys --armor <KEY-ID> > key.asc`
    /// --cipher-suite selects the subkey type: cv25519 / ecdh-* add an
    /// encryption subkey, ed25519-sign / ecdsa-*-sign add a signing subkey
    /// The primary key and its existing subkeys are kept as they are
    #[arg(long, value_name = "PATH", verbatim_doc_comment)]
    pub key_file: Option<String>,

    /// Select a key by fingerprint or key ID when --key-file contains several keys
    #[arg(long, value_name = "KEY_ID", requires = "key_file")]
    pub key_id: Option<String>,

    /// Passphrase of the key given by --key-file, if it is protected
    #[arg(long, value_name = "PASSPHRASE", requires = "key_file")]
    pub passphrase: Option<String>,

    /// Read the passphrase of --key-file from the first line of a file
    #[arg(
        long,
        value_name = "PATH",
        requires = "key_file",
        conflicts_with = "passphrase"
    )]
    pub passphrase_file: Option<String>,

    /// Search on the CPU instead of the GPU
    /// No OpenCL device is opened or used, so this works even when there is no
    /// usable device. The binary still links against the OpenCL runtime.
    /// --thread and --iteration do not apply.
    #[arg(long, default_value_t = false, verbatim_doc_comment)]
    pub cpu: bool,

    /// Number of CPU threads to use with --cpu [default: logical CPUs]
    #[arg(long, value_name = "N", requires = "cpu")]
    pub cpu_threads: Option<usize>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuite::Ed25519,
            user_id: String::from("Dummy <dummy@example.com>"),
            pattern: vec![String::from("XXXYYYZZZWWW")],
            algorithm: vec![],
            filter: None,
            output: None,
            device: None,
            thread: None,
            iteration: 512,
            timeout: None,
            oneshot: true,
            shot_all: false,
            no_progress: true,
            no_secret_key_logging: false,
            list_device: false,
            future_timestamp: false,
            start_timestamp: None,
            max_time_range: None,
            key_file: None,
            key_id: None,
            passphrase: None,
            passphrase_file: None,
            cpu: false,
            cpu_threads: None,
        }
    }
}

/// Cipher Suites
#[derive(ValueEnum, Default, Clone, Copy, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum CipherSuite {
    #[default]
    Ed25519,
    Cv25519,
    RSA2048,
    RSA3072,
    RSA4096,
    EcdhP256,
    EcdhP384,
    EcdhP521,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519Sign,
    EcdsaP256Sign,
    EcdsaP384Sign,
    EcdsaP521Sign,
}

impl CipherSuite {
    /// The key packet that is searched on the GPU when no target is given.
    pub fn default_target(self) -> KeyTarget {
        match self {
            Self::Cv25519 | Self::EcdhP256 | Self::EcdhP384 | Self::EcdhP521 => KeyTarget::Encrypt,
            Self::Ed25519Sign | Self::EcdsaP256Sign | Self::EcdsaP384Sign | Self::EcdsaP521Sign => {
                KeyTarget::Sign
            }
            _ => KeyTarget::Primary,
        }
    }

    /// The subkey this suite adds when a key is imported with `--key-file`.
    pub fn subkey_spec(self) -> anyhow::Result<(KeyType, KeyTarget)> {
        Ok(match self {
            Self::Cv25519 => (KeyType::ECDH(ECCCurve::Curve25519), KeyTarget::Encrypt),
            Self::EcdhP256 => (KeyType::ECDH(ECCCurve::P256), KeyTarget::Encrypt),
            Self::EcdhP384 => (KeyType::ECDH(ECCCurve::P384), KeyTarget::Encrypt),
            Self::EcdhP521 => (KeyType::ECDH(ECCCurve::P521), KeyTarget::Encrypt),
            Self::Ed25519Sign => (KeyType::EdDSALegacy, KeyTarget::Sign),
            Self::EcdsaP256Sign => (KeyType::ECDSA(ECCCurve::P256), KeyTarget::Sign),
            Self::EcdsaP384Sign => (KeyType::ECDSA(ECCCurve::P384), KeyTarget::Sign),
            Self::EcdsaP521Sign => (KeyType::ECDSA(ECCCurve::P521), KeyTarget::Sign),
            _ => bail!(
                "--key-file appends a subkey, so --cipher-suite must name a subkey type: \
                 cv25519, ecdh-p256, ecdh-p384, ecdh-p521, ed25519-sign, \
                 ecdsa-p256-sign, ecdsa-p384-sign or ecdsa-p521-sign"
            ),
        })
    }
}

/// A key packet of the generated key that a pattern can be matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyTarget {
    /// The primary key packet.
    Primary,
    /// The signing subkey (only present in `*-sign` cipher suites).
    Sign,
    /// The encryption subkey (absent for RSA keys).
    Encrypt,
}

impl KeyTarget {
    pub fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary key",
            Self::Sign => "signing subkey",
            Self::Encrypt => "encryption subkey",
        }
    }
}

impl FromStr for KeyTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "primary" | "p" | "main" | "primary-key" => Ok(Self::Primary),
            "sign" | "s" | "signing" | "signing-subkey" | "sign-subkey" => Ok(Self::Sign),
            "encrypt" | "e" | "enc" | "sub" | "subkey" | "encryption" | "encryption-subkey" => {
                Ok(Self::Encrypt)
            }
            _ => bail!("Unknown key target \"{s}\" (expected one of: primary, sign, encrypt)"),
        }
    }
}
