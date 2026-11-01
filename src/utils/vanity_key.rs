use anyhow::{anyhow, bail, ensure, Result};
use byteorder::{BigEndian, ByteOrder};
use chrono::SubsecRound;
use log::{debug, info};
use pgp::{
    composed::{key::SecretKeyParamsBuilder, KeyType, SignedSecretSubKey},
    crypto::{
        ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{
        KeyFlags, PacketTrait, PublicSubkey as PacketPublicSubkey,
        SecretSubkey as PacketSecretSubkey, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, Fingerprint, KeyVersion, PublicKeyTrait, SecretKeyTrait,
        SecretParams, Version,
    },
    Deserializable, SecretKey, SecretSubkey, SignedSecretKey, SubkeyParamsBuilder,
};
use rand::{CryptoRng, Rng};
use smallvec::smallvec;

use crate::ARGS;

use super::{CipherSuite, KeyTarget};

/// Get the data used to calculate the fingerprint of a private key
fn build_secret_key_hashdata(secret_key: impl SecretKeyTrait) -> Vec<u8> {
    let mut hashdata = vec![0x99, 0, 0, 0x04, 0, 0, 0, 0];
    BigEndian::write_u32(
        &mut hashdata[4..8],
        secret_key.created_at().timestamp() as u32,
    );
    hashdata.push(secret_key.algorithm().into());
    secret_key.public_params().to_writer(&mut hashdata).unwrap();
    let packet_len = (hashdata.len() - 3) as u16;
    BigEndian::write_u16(&mut hashdata[1..3], packet_len);
    hashdata
}

/// Create a key binding signature over `primary` and `subkey`, in that order,
/// signed by `signer`.
///
/// `SignatureConfig::sign_key_binding` always hashes the signing key first,
/// which is correct for a regular subkey binding signature but not for a
/// primary key binding ("back") signature, where the primary key must be hashed
/// first even though the subkey signs. This helper takes the hash order
/// explicitly. `passphrase` unlocks the signing key.
fn create_key_binding_signature(
    config: SignatureConfig,
    signer: &impl SecretKeyTrait,
    primary: &impl PublicKeyTrait,
    subkey: &impl PublicKeyTrait,
    passphrase: &str,
) -> Result<Signature> {
    let mut hasher = config.hash_alg.new_hasher()?;
    let mut key_buf = Vec::new();

    primary.serialize_for_hashing(&mut key_buf)?;
    hasher.update(&key_buf);
    key_buf.clear();
    subkey.serialize_for_hashing(&mut key_buf)?;
    hasher.update(&key_buf);

    let len = config.hash_signature_data(&mut hasher)?;
    hasher.update(&config.trailer(len)?);

    let hash = hasher.finish();
    let signed_hash_value = [hash[0], hash[1]];
    let signature = signer.create_signature(|| passphrase.to_string(), config.hash_alg, &hash)?;

    Ok(Signature::from_config(config, signed_hash_value, signature))
}

/// Create a cross-certified subkey binding signature for a signing subkey.
///
/// GnuPG rejects signatures made by a signing subkey unless the subkey binding
/// signature carries an embedded Primary Key Binding Signature ("back
/// signature") made by the subkey itself.
fn signing_subkey_binding_signature(
    primary_key: &impl SecretKeyTrait,
    subkey: &impl SecretKeyTrait,
    keyflags: KeyFlags,
    passphrase: &str,
) -> Result<Signature> {
    let created_at = chrono::Utc::now().trunc_subsecs(0);

    // Primary Key Binding Signature (0x19), made by the subkey.
    let mut back_config = SignatureConfig::v4(
        SignatureType::KeyBinding,
        subkey.algorithm(),
        subkey.hash_alg(),
    );
    back_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created_at)),
        Subpacket::regular(SubpacketData::IssuerFingerprint(subkey.fingerprint())),
    ];
    back_config.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::Issuer(subkey.key_id()))];
    let back_signature =
        create_key_binding_signature(back_config, subkey, primary_key, subkey, passphrase)?;

    // Subkey Binding Signature (0x18), made by the primary key, carrying the
    // back signature as an embedded signature subpacket.
    let mut binding_config = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        primary_key.algorithm(),
        primary_key.hash_alg(),
    );
    binding_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created_at)),
        Subpacket::regular(SubpacketData::KeyFlags(keyflags.into())),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint())),
        Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(back_signature))),
    ];
    binding_config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
        primary_key.key_id(),
    ))];

    create_key_binding_signature(binding_config, primary_key, primary_key, subkey, passphrase)
}

/// Create a regular subkey binding signature for a subkey that does not need a
/// cross-certification (encryption subkeys). `SignatureConfig::sign_key_binding`
/// hashes the primary key first, which is exactly right here.
fn regular_subkey_binding_signature(
    primary_key: &impl SecretKeyTrait,
    subkey: &impl PublicKeyTrait,
    keyflags: KeyFlags,
    passphrase: &str,
) -> Result<Signature> {
    let mut config = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        primary_key.algorithm(),
        primary_key.hash_alg(),
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            chrono::Utc::now().trunc_subsecs(0),
        )),
        Subpacket::regular(SubpacketData::KeyFlags(keyflags.into())),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint())),
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
        primary_key.key_id(),
    ))];

    Ok(config.sign_key_binding(primary_key, || passphrase.to_string(), subkey)?)
}

/// Replace the binding signatures of signing subkeys with cross-certified ones.
fn cross_certify_signing_subkeys(
    key: &mut SignedSecretKey,
    subkey_flags: &[KeyFlags],
) -> Result<()> {
    debug_assert_eq!(key.secret_subkeys.len(), subkey_flags.len());

    for (index, keyflags) in subkey_flags.iter().enumerate() {
        if !keyflags.sign() {
            continue;
        }

        key.secret_subkeys[index].signatures = vec![signing_subkey_binding_signature(
            &key.primary_key,
            &key.secret_subkeys[index].key,
            *keyflags,
            "",
        )?];
    }

    Ok(())
}

/// Bookkeeping for a subkey appended to an imported key.
#[derive(Debug, Clone)]
struct AppendedSubkey {
    /// Index in `secret_key.secret_subkeys`.
    index: usize,
    /// What the new subkey is for.
    target: KeyTarget,
    /// Type of the key material generated for the subkey.
    key_type: KeyType,
    /// Whether the imported key is passphrase-protected (the new subkey
    /// inherits that protection).
    protected: bool,
}

#[derive(Clone)]
pub struct VanitySecretKey {
    pub secret_key: SignedSecretKey,
    /// Key flags of the subkeys, in the same order as `secret_key.secret_subkeys`.
    /// The crate does not expose them after generation, so keep our own copy to
    /// re-sign the key without changing the intended capabilities.
    subkey_flags: Vec<KeyFlags>,
    /// Set when the key was imported with `--key-file`: only this subkey is
    /// searched. Every candidate gets fresh key material and a creation time
    /// from the searched range.
    appended: Option<AppendedSubkey>,
    /// Passphrase of the imported key (empty for freshly generated keys),
    /// needed to re-sign the subkey binding when a match is found.
    passphrase: String,
}

fn add_encryption_subkey(
    builder: &mut SecretKeyParamsBuilder,
    curve: ECCCurve,
    subkey_flags: &mut Vec<KeyFlags>,
) {
    let mut subkey_params_builder = SubkeyParamsBuilder::default();
    subkey_params_builder
        .key_type(KeyType::ECDH(curve))
        .can_encrypt(true);
    builder.subkey(subkey_params_builder.build().unwrap());

    let mut flags = KeyFlags::default();
    flags.set_encrypt_comms(true);
    flags.set_encrypt_storage(true);
    subkey_flags.push(flags);
}

fn add_signing_subkey(
    builder: &mut SecretKeyParamsBuilder,
    key_type: KeyType,
    subkey_flags: &mut Vec<KeyFlags>,
) {
    let mut subkey_params_builder = SubkeyParamsBuilder::default();
    subkey_params_builder.key_type(key_type).can_sign(true);
    builder.subkey(subkey_params_builder.build().unwrap());

    let mut flags = KeyFlags::default();
    flags.set_sign(true);
    subkey_flags.push(flags);
}

/// A packet inside the generated key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPacket {
    Primary,
    Subkey(usize),
}

impl VanitySecretKey {
    /// Resolve a target to the packet it refers to.
    ///
    /// The subkey is looked up by its key flags instead of a hard-coded index,
    /// so this keeps working if the key layout changes.
    pub fn resolve_target(&self, target: KeyTarget) -> Result<KeyPacket> {
        if let Some(appended) = self.appended.as_ref() {
            return if target == appended.target {
                Ok(KeyPacket::Subkey(appended.index))
            } else if target == KeyTarget::Primary {
                Err(anyhow!(
                    "The primary key of an imported key cannot be searched: its fingerprint is fixed. Only the new {} is searched",
                    appended.target.label()
                ))
            } else {
                Err(anyhow!(
                    "Only the new {} is searched in --key-file mode; the existing key packets are kept as they are",
                    appended.target.label()
                ))
            };
        }

        match target {
            KeyTarget::Primary => Ok(KeyPacket::Primary),
            KeyTarget::Sign => self
                .subkey_flags
                .iter()
                .position(|flags| flags.sign())
                .map(KeyPacket::Subkey)
                .ok_or_else(|| {
                    anyhow!(
                        "This cipher suite has no signing subkey; use a `*-sign` cipher suite (e.g. `-c ed25519-sign`) to create one"
                    )
                }),
            KeyTarget::Encrypt => self
                .subkey_flags
                .iter()
                .position(|flags| flags.encrypt_comms() || flags.encrypt_storage())
                .map(KeyPacket::Subkey)
                .ok_or_else(|| {
                    anyhow!(
                        "This cipher suite has no encryption subkey (RSA keys have none); choose another cipher suite"
                    )
                }),
        }
    }

    /// The key packets this key has, in a stable order.
    pub fn available_targets(&self) -> Vec<KeyTarget> {
        if let Some(appended) = self.appended.as_ref() {
            return vec![appended.target];
        }

        let mut targets = vec![KeyTarget::Primary];
        if self.subkey_flags.iter().any(|flags| flags.sign()) {
            targets.push(KeyTarget::Sign);
        }
        if self
            .subkey_flags
            .iter()
            .any(|flags| flags.encrypt_comms() || flags.encrypt_storage())
        {
            targets.push(KeyTarget::Encrypt);
        }
        targets
    }

    /// The fingerprint of the packet a target refers to.
    pub fn fingerprint_for(&self, target: KeyTarget) -> pgp::types::Fingerprint {
        match self
            .resolve_target(target)
            .expect("key targets are validated before the search starts")
        {
            KeyPacket::Primary => self.secret_key.fingerprint(),
            KeyPacket::Subkey(index) => self.secret_key.secret_subkeys[index].fingerprint(),
        }
    }

    /// The target of the subkey appended to an imported key, if any.
    pub fn appended_target(&self) -> Option<KeyTarget> {
        self.appended.as_ref().map(|appended| appended.target)
    }

    /// The fingerprint of the subkey appended to an imported key, if any.
    pub fn appended_fingerprint(&self) -> Option<Fingerprint> {
        self.appended
            .as_ref()
            .map(|appended| self.secret_key.secret_subkeys[appended.index].fingerprint())
    }

    /// Creation time of the primary key, used to keep an appended subkey from
    /// being placed before it.
    pub fn primary_created_at(&self) -> u32 {
        self.secret_key.created_at().timestamp() as u32
    }
}

impl VanitySecretKey {
    pub fn new(cipher_suite: CipherSuite, user_id: String, mut rng: impl Rng + CryptoRng) -> Self {
        let mut secret_key_params_builder = SecretKeyParamsBuilder::default();
        secret_key_params_builder
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::SHA2_512,
                HashAlgorithm::SHA2_384,
                HashAlgorithm::SHA2_256,
                HashAlgorithm::SHA2_224,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::BZip2,
                CompressionAlgorithm::ZIP,
                CompressionAlgorithm::Uncompressed,
            ])
            .primary_user_id(user_id);

        let mut subkey_flags = Vec::new();

        match cipher_suite {
            // Ed25519 primary [SC] + Curve25519 encryption subkey [E].
            CipherSuite::Ed25519 | CipherSuite::Cv25519 => {
                secret_key_params_builder
                    .key_type(KeyType::EdDSALegacy)
                    .can_certify(true)
                    .can_sign(true);
                add_encryption_subkey(
                    &mut secret_key_params_builder,
                    ECCCurve::Curve25519,
                    &mut subkey_flags,
                );
            }
            // Ed25519 primary [C] + Ed25519 signing subkey [S]
            // + Curve25519 encryption subkey [E].
            CipherSuite::Ed25519Sign => {
                secret_key_params_builder
                    .key_type(KeyType::EdDSALegacy)
                    .can_certify(true);
                add_signing_subkey(
                    &mut secret_key_params_builder,
                    KeyType::EdDSALegacy,
                    &mut subkey_flags,
                );
                add_encryption_subkey(
                    &mut secret_key_params_builder,
                    ECCCurve::Curve25519,
                    &mut subkey_flags,
                );
            }
            // ECDSA primary [SC] + ECDH encryption subkey [E].
            CipherSuite::EcdhP256
            | CipherSuite::EcdsaP256
            | CipherSuite::EcdhP384
            | CipherSuite::EcdsaP384
            | CipherSuite::EcdhP521
            | CipherSuite::EcdsaP521 => {
                let curve = match cipher_suite {
                    CipherSuite::EcdhP256 | CipherSuite::EcdsaP256 => ECCCurve::P256,
                    CipherSuite::EcdhP384 | CipherSuite::EcdsaP384 => ECCCurve::P384,
                    CipherSuite::EcdhP521 | CipherSuite::EcdsaP521 => ECCCurve::P521,
                    _ => unreachable!(),
                };
                secret_key_params_builder
                    .key_type(KeyType::ECDSA(curve.clone()))
                    .can_certify(true)
                    .can_sign(true);
                add_encryption_subkey(&mut secret_key_params_builder, curve, &mut subkey_flags);
            }
            // ECDSA primary [C] + ECDSA signing subkey [S]
            // + ECDH encryption subkey [E].
            CipherSuite::EcdsaP256Sign
            | CipherSuite::EcdsaP384Sign
            | CipherSuite::EcdsaP521Sign => {
                let curve = match cipher_suite {
                    CipherSuite::EcdsaP256Sign => ECCCurve::P256,
                    CipherSuite::EcdsaP384Sign => ECCCurve::P384,
                    CipherSuite::EcdsaP521Sign => ECCCurve::P521,
                    _ => unreachable!(),
                };
                secret_key_params_builder
                    .key_type(KeyType::ECDSA(curve.clone()))
                    .can_certify(true);
                add_signing_subkey(
                    &mut secret_key_params_builder,
                    KeyType::ECDSA(curve.clone()),
                    &mut subkey_flags,
                );
                add_encryption_subkey(&mut secret_key_params_builder, curve, &mut subkey_flags);
            }
            CipherSuite::RSA2048 | CipherSuite::RSA3072 | CipherSuite::RSA4096 => {
                let bits = match cipher_suite {
                    CipherSuite::RSA2048 => 2048,
                    CipherSuite::RSA3072 => 3072,
                    CipherSuite::RSA4096 => 4096,
                    _ => unreachable!(),
                };
                secret_key_params_builder
                    .key_type(KeyType::Rsa(bits))
                    .can_certify(true)
                    .can_sign(true)
                    .can_encrypt(true);
            }
        }

        let secret_key_params = secret_key_params_builder.build().unwrap();
        let mut secret_key = secret_key_params
            .generate(&mut rng)
            .unwrap()
            .sign(&mut rng, String::new)
            .unwrap();
        cross_certify_signing_subkeys(&mut secret_key, &subkey_flags).unwrap();
        assert_eq!(secret_key.version(), KeyVersion::V4);

        Self {
            secret_key,
            subkey_flags,
            appended: None,
            passphrase: String::new(),
        }
    }

    /// Append a new vanity subkey to an existing secret key.
    ///
    /// The primary key and its existing subkeys are left untouched; the search
    /// generates fresh key material for the new subkey and varies its creation
    /// time. `cipher_suite` must name a subkey type (`cv25519`, `ecdh-*`,
    /// `ed25519-sign`, `ecdsa-*-sign`). `passphrase` unlocks the existing key
    /// (empty if it is not protected) and is also used to protect the new
    /// subkey when the existing key is protected.
    pub fn from_existing(
        secret_key: SignedSecretKey,
        cipher_suite: CipherSuite,
        passphrase: String,
        mut rng: impl Rng + CryptoRng,
    ) -> Result<Self> {
        ensure!(
            secret_key.version() == KeyVersion::V4,
            "Only v4 keys can be extended (this key is {:?}); v6 keys use SHA-256 fingerprints, which the GPU kernel does not support",
            secret_key.version()
        );
        ensure!(
            matches!(
                secret_key.primary_key.algorithm(),
                PublicKeyAlgorithm::RSA
                    | PublicKeyAlgorithm::RSASign
                    | PublicKeyAlgorithm::DSA
                    | PublicKeyAlgorithm::ECDSA
                    | PublicKeyAlgorithm::EdDSALegacy
                    | PublicKeyAlgorithm::Ed25519
                    | PublicKeyAlgorithm::Ed448
                    | PublicKeyAlgorithm::ElgamalSign
            ),
            "The primary key algorithm ({:?}) cannot sign, so it cannot certify a new subkey",
            secret_key.primary_key.algorithm()
        );

        let (key_type, target) = cipher_suite.subkey_spec()?;

        let mut flags = KeyFlags::default();
        match target {
            KeyTarget::Encrypt => {
                flags.set_encrypt_comms(true);
                flags.set_encrypt_storage(true);
            }
            KeyTarget::Sign => flags.set_sign(true),
            KeyTarget::Primary => unreachable!("subkey_spec never returns the primary key"),
        }

        // The new subkey inherits the protection of the imported key.
        let protected = matches!(
            secret_key.primary_key.secret_params(),
            SecretParams::Encrypted(_)
        );
        if protected {
            secret_key
                .primary_key
                .unlock(|| passphrase.clone(), |_| Ok(()))
                .map_err(|e| {
                    anyhow!("Failed to unlock the existing key with the given passphrase: {e}")
                })?;
        }

        // Keep one flag set per subkey, in the same order as `secret_subkeys`.
        let mut subkey_flags: Vec<KeyFlags> = secret_key
            .secret_subkeys
            .iter()
            .map(|subkey| {
                subkey
                    .signatures
                    .first()
                    .map(|signature| signature.key_flags())
                    .unwrap_or_default()
            })
            .collect();
        let index = secret_key.secret_subkeys.len();
        subkey_flags.push(flags);

        let mut key = Self {
            secret_key,
            subkey_flags,
            appended: Some(AppendedSubkey {
                index,
                target,
                key_type,
                protected,
            }),
            passphrase,
        };
        key.replace_appended_subkey(chrono::Utc::now().timestamp() as u32, &mut rng)?;
        Ok(key)
    }

    /// A copy of this key with fresh key material for the appended subkey.
    ///
    /// The subkey is not signed here: candidates only need their public key to
    /// be hashed, and the binding signature is created when one matches.
    pub fn new_candidate(&self, timestamp: u32, mut rng: impl Rng + CryptoRng) -> Result<Self> {
        let mut candidate = self.clone();
        candidate.replace_appended_subkey(timestamp, &mut rng)?;
        Ok(candidate)
    }

    /// Replace the appended subkey with newly generated key material.
    fn replace_appended_subkey(
        &mut self,
        timestamp: u32,
        mut rng: impl Rng + CryptoRng,
    ) -> Result<()> {
        let appended = self
            .appended
            .clone()
            .ok_or_else(|| anyhow!("This key has no appended subkey"))?;
        let created_at = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .ok_or_else(|| anyhow!("Invalid timestamp {timestamp}"))?;

        let (public_params, secret_params) = appended.key_type.generate(&mut rng)?;
        let public_subkey = PacketPublicSubkey::new(
            Version::New,
            KeyVersion::V4,
            appended.key_type.to_alg(),
            created_at,
            None,
            public_params,
        )?;
        // Candidates stay unprotected while searching: protecting the secret
        // key material with the S2K function on every round would be the
        // bottleneck of the whole search. The matched key is protected before
        // it is written out (see `protect_appended_subkey`).
        let subkey = PacketSecretSubkey::new(public_subkey, secret_params);

        let signed = SignedSecretSubKey::new(subkey, Vec::new());
        if appended.index == self.secret_key.secret_subkeys.len() {
            // First candidate: the appended subkey slot does not exist yet.
            self.secret_key.secret_subkeys.push(signed);
        } else {
            self.secret_key.secret_subkeys[appended.index] = signed;
        }
        Ok(())
    }

    /// Protect the appended subkey with the passphrase of the imported key,
    /// if that key is protected. Called once a candidate has matched.
    pub fn protect_appended_subkey(&mut self, mut rng: impl Rng + CryptoRng) -> Result<()> {
        let Some(appended) = self.appended.clone() else {
            return Ok(());
        };
        if !appended.protected {
            return Ok(());
        }
        if matches!(
            self.secret_key.secret_subkeys[appended.index]
                .key
                .secret_params(),
            SecretParams::Encrypted(_)
        ) {
            return Ok(());
        }

        let passphrase = self.passphrase.clone();
        self.secret_key.secret_subkeys[appended.index]
            .key
            .set_password(&mut rng, || passphrase.clone())?;
        Ok(())
    }

    pub fn edit_timestamp(&mut self, timestamp: u32, mut rng: impl Rng + CryptoRng) -> Result<()> {
        if let Some(appended) = self.appended.clone() {
            return self.set_subkey_timestamp(appended, timestamp);
        }

        // RFC 9580 - OpenPGP
        // 4. Packet Syntax
        // https://datatracker.ietf.org/doc/html/rfc9580#name-packet-syntax
        let mut secret_key_bytes = self.secret_key.to_bytes()?;
        let mut packet_read_pos: usize = 0;
        while packet_read_pos < secret_key_bytes.len() {
            let cipher_type_byte = secret_key_bytes[packet_read_pos];
            debug!("cipher_type_byte = {:#04X}", cipher_type_byte);
            packet_read_pos += 1;
            let (size, size_length) = match cipher_type_byte >> 6 {
                0b10 => match cipher_type_byte & 0b00000011 {
                    0 => (secret_key_bytes[packet_read_pos] as usize, 1),
                    1 => (
                        BigEndian::read_u16(&secret_key_bytes[packet_read_pos..packet_read_pos + 2])
                            as usize,
                        2,
                    ),
                    2 => (
                        BigEndian::read_u32(&secret_key_bytes[packet_read_pos..packet_read_pos + 4])
                            as usize,
                        4,
                    ),
                    3 => unimplemented!("Indeterminate length"),
                    _ => unreachable!(),
                },
                0b11 => match secret_key_bytes[packet_read_pos] {
                    x if x < 192 => (secret_key_bytes[packet_read_pos] as usize, 1),
                    x if x < 224 => (
                        (((secret_key_bytes[packet_read_pos] - 192) as usize) << 8)
                            + (secret_key_bytes[packet_read_pos + 1] as usize)
                            + 192,
                        2,
                    ),
                    255 => (
                        BigEndian::read_u32(
                            &secret_key_bytes[packet_read_pos + 1..packet_read_pos + 5],
                        ) as usize,
                        5,
                    ),
                    _ => unimplemented!("Partial body length"),
                },
                _ => unreachable!(),
            };
            debug!("size = {size}, size_length = {size_length}");
            packet_read_pos += size_length;
            let packet_type = match cipher_type_byte >> 6 {
                0b10 => (cipher_type_byte & 0b00111100) >> 2,
                0b11 => cipher_type_byte & 0b00111111,
                _ => unreachable!(),
            };
            debug!("packet_type = {packet_type:#04X}");
            // 0x05 => Secret-Key Packet
            // 0x07 => Secret-Subkey Packet
            if [0x05, 0x07].contains(&packet_type) {
                BigEndian::write_u32(
                    &mut secret_key_bytes[packet_read_pos + 1..packet_read_pos + 5],
                    timestamp,
                );
            }
            packet_read_pos += size;
        }

        // The signature of this key is invalid because only the timestamp is modified
        let edited_key = SignedSecretKey::from_bytes(&secret_key_bytes[..])?;

        // Re-sign the key, keeping the original capabilities of each subkey
        // (encryption subkeys must stay encryption-only, signing subkeys must
        // stay signing-only).
        debug_assert_eq!(edited_key.secret_subkeys.len(), self.subkey_flags.len());
        let subkey_flags = self.subkey_flags.clone();
        let mut re_signed_key = SecretKey::new(
            edited_key.primary_key,
            edited_key.details.as_unsigned(),
            edited_key
                .public_subkeys
                .iter()
                .map(|e| e.as_unsigned())
                .collect(),
            edited_key
                .secret_subkeys
                .iter()
                .zip(subkey_flags.iter().copied())
                .map(|(e, flags)| SecretSubkey::new(e.key.clone(), flags))
                .collect(),
        )
        .sign(&mut rng, String::new)?;
        cross_certify_signing_subkeys(&mut re_signed_key, &subkey_flags)?;
        self.secret_key = re_signed_key;
        Ok(())
    }

    /// Move the appended subkey to `timestamp` and re-sign its binding
    /// signature, leaving every other packet of the imported key untouched.
    fn set_subkey_timestamp(&mut self, appended: AppendedSubkey, timestamp: u32) -> Result<()> {
        let created_at = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .ok_or_else(|| anyhow!("Invalid timestamp {timestamp}"))?;

        // Rebuild only the subkey packet: same key material, new creation time.
        // The secret parameters keep their original protection, but the
        // signature is still computed by unlocking them with the stored
        // passphrase.
        let subkey = {
            let old = &self.secret_key.secret_subkeys[appended.index].key;
            let public_subkey = PacketPublicSubkey::new(
                old.packet_version(),
                old.version(),
                old.algorithm(),
                created_at,
                old.expiration(),
                old.public_params().clone(),
            )?;
            PacketSecretSubkey::new(public_subkey, old.secret_params().clone())
        };

        let flags = self.subkey_flags[appended.index];
        let signatures = if appended.target == KeyTarget::Sign {
            vec![signing_subkey_binding_signature(
                &self.secret_key.primary_key,
                &subkey,
                flags,
                &self.passphrase,
            )?]
        } else {
            vec![regular_subkey_binding_signature(
                &self.secret_key.primary_key,
                &subkey,
                flags,
                &self.passphrase,
            )?]
        };

        self.secret_key.secret_subkeys[appended.index] =
            SignedSecretSubKey::new(subkey, signatures);
        Ok(())
    }

    /// The data hashed into the fingerprint of the packet a target refers to.
    pub fn hashdata_for(&self, target: KeyTarget) -> Vec<u8> {
        match self
            .resolve_target(target)
            .expect("key targets are validated before the search starts")
        {
            KeyPacket::Primary => build_secret_key_hashdata(&self.secret_key),
            KeyPacket::Subkey(index) => {
                build_secret_key_hashdata(&self.secret_key.secret_subkeys[index])
            }
        }
    }

    pub fn to_armored_string(&self) -> Result<String> {
        Ok(self
            .secret_key
            .to_armored_string(pgp::ArmorOptions::default())?)
    }

    pub fn log_state(&self) {
        if ARGS.no_secret_key_logging {
            info!("Get a vanity key!");
        } else {
            info!(
                "Get a vanity key: \n{}",
                self.to_armored_string().unwrap_or_default()
            );
        }
        info!(
            "Created at: {} ({})",
            self.secret_key
                .created_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            self.secret_key.created_at().timestamp(),
        );
        info!(
            "Fingerprint #0: {}",
            hex::encode_upper(self.secret_key.fingerprint().as_bytes())
        );
        for (i, subkey) in self.secret_key.secret_subkeys.iter().enumerate() {
            info!(
                "Fingerprint #{}: {}",
                i + 1,
                hex::encode_upper(subkey.fingerprint().as_bytes())
            );
        }
        if let (Some(appended), Some(fingerprint)) =
            (self.appended.as_ref(), self.appended_fingerprint())
        {
            info!(
                "The new {} is #{} in the list above: {}",
                appended.target.label(),
                appended.index + 1,
                hex::encode_upper(fingerprint.as_bytes())
            );
        }
    }
}

/// Load one secret key from an exported key file (ASCII-armored or binary).
///
/// `selector` picks a key by (a suffix of) its primary fingerprint or key ID
/// when the file contains more than one key.
pub fn load_secret_key(
    reader: impl std::io::Read,
    selector: Option<&str>,
) -> Result<SignedSecretKey> {
    let (keys, _) = SignedSecretKey::from_reader_many(reader)?;
    let mut keys = keys.collect::<std::result::Result<Vec<_>, _>>()?;

    if keys.is_empty() {
        bail!(
            "No secret key found in the given file. Export one with `gpg --export-secret-keys --armor <KEY-ID>`"
        );
    }

    let all_fingerprints = keys
        .iter()
        .map(|key| hex::encode_upper(key.fingerprint().as_bytes()))
        .collect::<Vec<_>>()
        .join(", ");

    let Some(selector) = selector else {
        if keys.len() > 1 {
            bail!(
                "The file contains {} secret keys ({all_fingerprints}); select one with --key-id",
                keys.len()
            );
        }
        return Ok(keys.remove(0));
    };

    let normalized = normalize_key_selector(selector)?;
    let mut matches: Vec<SignedSecretKey> = keys
        .into_iter()
        .filter(|key| hex::encode_upper(key.fingerprint().as_bytes()).ends_with(&normalized))
        .collect();

    match matches.len() {
        0 => bail!(
            "No secret key matches --key-id \"{selector}\". Keys in the file: {all_fingerprints}"
        ),
        1 => Ok(matches.remove(0)),
        count => bail!(
            "--key-id \"{selector}\" matches {count} keys; give more digits of the fingerprint"
        ),
    }
}

/// Normalize a key ID / fingerprint given on the command line.
fn normalize_key_selector(selector: &str) -> Result<String> {
    let normalized = selector
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_uppercase();

    ensure!(!normalized.is_empty(), "Empty --key-id");
    ensure!(
        normalized.len() >= 8,
        "--key-id must be at least a short key ID (8 hex digits) or a full fingerprint"
    );
    ensure!(
        normalized.len() <= 40,
        "--key-id is longer than a full fingerprint (40 hex digits)"
    );
    ensure!(
        normalized.chars().all(|c| c.is_ascii_hexdigit()),
        "--key-id must be hexadecimal"
    );

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn sha1_of_hashdata(key: &VanitySecretKey, target: KeyTarget) -> Vec<u8> {
        HashAlgorithm::SHA1
            .digest(&key.hashdata_for(target))
            .unwrap()
    }

    fn subkey_flags(key: &VanitySecretKey, index: usize) -> KeyFlags {
        key.secret_key.secret_subkeys[index].signatures[0].key_flags()
    }

    #[test]
    fn primary_suites_search_the_primary_key() {
        for suite in [
            CipherSuite::Ed25519,
            CipherSuite::EcdsaP256,
            CipherSuite::EcdsaP384,
            CipherSuite::EcdsaP521,
        ] {
            let key = VanitySecretKey::new(suite, "Test <test@example.com>".into(), thread_rng());
            assert_eq!(
                sha1_of_hashdata(&key, KeyTarget::Primary),
                key.secret_key.fingerprint().as_bytes(),
                "{suite:?}"
            );
        }
    }

    #[test]
    fn encryption_subkey_suites_search_the_encryption_subkey() {
        for suite in [
            CipherSuite::Cv25519,
            CipherSuite::EcdhP256,
            CipherSuite::EcdhP384,
            CipherSuite::EcdhP521,
        ] {
            let key = VanitySecretKey::new(suite, "Test <test@example.com>".into(), thread_rng());
            assert_eq!(
                sha1_of_hashdata(&key, KeyTarget::Encrypt),
                key.secret_key.secret_subkeys[0].fingerprint().as_bytes(),
                "{suite:?}"
            );
            assert!(subkey_flags(&key, 0).encrypt_comms(), "{suite:?}");
            assert!(!subkey_flags(&key, 0).sign(), "{suite:?}");
        }
    }

    #[test]
    fn signing_subkey_suites_search_the_signing_subkey() {
        for suite in [
            CipherSuite::Ed25519Sign,
            CipherSuite::EcdsaP256Sign,
            CipherSuite::EcdsaP384Sign,
            CipherSuite::EcdsaP521Sign,
        ] {
            let key = VanitySecretKey::new(suite, "Test <test@example.com>".into(), thread_rng());

            // Primary [C], signing subkey [S], encryption subkey [E].
            assert_eq!(key.secret_key.secret_subkeys.len(), 2, "{suite:?}");
            assert!(subkey_flags(&key, 0).sign(), "{suite:?}");
            assert!(!subkey_flags(&key, 0).encrypt_comms(), "{suite:?}");
            assert!(subkey_flags(&key, 1).encrypt_comms(), "{suite:?}");
            assert!(!subkey_flags(&key, 1).sign(), "{suite:?}");

            // The GPU searches the signing subkey's fingerprint.
            assert_eq!(
                sha1_of_hashdata(&key, KeyTarget::Sign),
                key.secret_key.secret_subkeys[0].fingerprint().as_bytes(),
                "{suite:?}"
            );
        }
    }

    #[test]
    fn edit_timestamp_keeps_subkey_capabilities() {
        let mut key = VanitySecretKey::new(
            CipherSuite::Ed25519Sign,
            "Test <test@example.com>".into(),
            thread_rng(),
        );
        key.edit_timestamp(1_600_000_000, thread_rng()).unwrap();

        assert_eq!(key.secret_key.created_at().timestamp(), 1_600_000_000);
        assert!(key
            .secret_key
            .secret_subkeys
            .iter()
            .all(|s| s.created_at().timestamp() == 1_600_000_000));

        // Flags must survive re-signing: the old implementation marked every
        // subkey as an encryption key.
        assert!(subkey_flags(&key, 0).sign());
        assert!(!subkey_flags(&key, 0).encrypt_comms());
        assert!(subkey_flags(&key, 1).encrypt_comms());
        assert!(!subkey_flags(&key, 1).sign());

        // The searched fingerprint still corresponds to the signed subkey.
        assert_eq!(
            sha1_of_hashdata(&key, KeyTarget::Sign),
            key.secret_key.secret_subkeys[0].fingerprint().as_bytes()
        );
    }

    #[test]
    fn every_target_of_a_signing_key_can_be_searched() {
        let key = VanitySecretKey::new(
            CipherSuite::Ed25519Sign,
            "Test <test@example.com>".into(),
            thread_rng(),
        );

        for (target, index) in [
            (KeyTarget::Primary, None),
            (KeyTarget::Sign, Some(0)),
            (KeyTarget::Encrypt, Some(1)),
        ] {
            let expected = match index {
                None => key.secret_key.fingerprint(),
                Some(index) => key.secret_key.secret_subkeys[index].fingerprint(),
            };
            assert_eq!(key.fingerprint_for(target).as_bytes(), expected.as_bytes());
            assert_eq!(sha1_of_hashdata(&key, target), expected.as_bytes());
        }
    }

    #[test]
    fn unavailable_targets_are_rejected() {
        let key = VanitySecretKey::new(
            CipherSuite::Ed25519,
            "Test <test@example.com>".into(),
            thread_rng(),
        );
        assert!(key.resolve_target(KeyTarget::Primary).is_ok());
        assert!(key.resolve_target(KeyTarget::Encrypt).is_ok());
        // A plain ed25519 key has no signing subkey.
        assert!(key.resolve_target(KeyTarget::Sign).is_err());
    }

    #[test]
    fn signing_subkey_is_cross_certified() {
        for suite in [
            CipherSuite::Ed25519Sign,
            CipherSuite::EcdsaP256Sign,
            CipherSuite::EcdsaP384Sign,
            CipherSuite::EcdsaP521Sign,
        ] {
            let mut key =
                VanitySecretKey::new(suite, "Test <test@example.com>".into(), thread_rng());
            key.edit_timestamp(1_600_000_000, thread_rng()).unwrap();

            let subkey = &key.secret_key.secret_subkeys[0];
            let binding = &subkey.signatures[0];
            let back_signature = binding
                .embedded_signature()
                .expect("signing subkey is not cross-certified");

            binding
                .verify_key_binding(&key.secret_key, &subkey.key)
                .expect("invalid subkey binding signature");
            back_signature
                .verify_backwards_key_binding(&subkey.key, &key.secret_key)
                .expect("invalid primary key binding signature");
        }
    }

    // -- Appending a subkey to an existing key ------------------------------

    fn existing_key() -> SignedSecretKey {
        VanitySecretKey::new(
            CipherSuite::Ed25519,
            "Test <test@example.com>".into(),
            thread_rng(),
        )
        .secret_key
    }

    fn fingerprints(key: &SignedSecretKey) -> Vec<String> {
        std::iter::once(key.fingerprint())
            .chain(key.secret_subkeys.iter().map(|s| s.fingerprint()))
            .map(|f| hex::encode_upper(f.as_bytes()))
            .collect()
    }

    #[test]
    fn appending_keeps_the_existing_key_untouched() {
        let existing = existing_key();
        let before = fingerprints(&existing);

        let mut key = VanitySecretKey::from_existing(
            existing,
            CipherSuite::Cv25519,
            String::new(),
            thread_rng(),
        )
        .unwrap();

        // Only one packet was added; everything that was there keeps its
        // fingerprint.
        let after = fingerprints(&key.secret_key);
        assert_eq!(after.len(), before.len() + 1);
        assert_eq!(&after[..before.len()], &before[..]);

        assert_eq!(key.appended_target(), Some(KeyTarget::Encrypt));
        assert_eq!(key.available_targets(), vec![KeyTarget::Encrypt]);
        // The fixed packets of an imported key must not be searchable.
        assert!(key.resolve_target(KeyTarget::Primary).is_err());
        assert!(key.resolve_target(KeyTarget::Sign).is_err());

        // The new subkey is the searched packet.
        assert_eq!(
            sha1_of_hashdata(&key, KeyTarget::Encrypt),
            key.secret_key
                .secret_subkeys
                .last()
                .unwrap()
                .fingerprint()
                .as_bytes()
        );

        // Candidates are unsigned until one matches; then the whole key verifies.
        key.edit_timestamp(1_600_000_000, thread_rng()).unwrap();
        key.secret_key.verify().unwrap();
    }

    #[test]
    fn appended_subkey_timestamp_can_be_edited() {
        let existing = existing_key();
        let primary_created_at = existing.created_at().timestamp();
        let old_subkey_created_at = existing.secret_subkeys[0].created_at().timestamp();

        let mut key = VanitySecretKey::from_existing(
            existing,
            CipherSuite::Cv25519,
            String::new(),
            thread_rng(),
        )
        .unwrap();
        key.edit_timestamp(1_600_000_000, thread_rng()).unwrap();

        // The imported packets keep their creation time...
        assert_eq!(key.secret_key.created_at().timestamp(), primary_created_at);
        assert_eq!(
            key.secret_key.secret_subkeys[0].created_at().timestamp(),
            old_subkey_created_at
        );
        // ...only the appended one moves.
        let index = key.secret_key.secret_subkeys.len() - 1;
        assert_eq!(
            key.secret_key.secret_subkeys[index]
                .created_at()
                .timestamp(),
            1_600_000_000
        );

        let subkey = &key.secret_key.secret_subkeys[index];
        assert!(subkey.signatures[0].key_flags().encrypt_comms());
        subkey.signatures[0]
            .verify_key_binding(&key.secret_key, &subkey.key)
            .expect("invalid subkey binding signature");
        assert_eq!(
            sha1_of_hashdata(&key, KeyTarget::Encrypt),
            subkey.fingerprint().as_bytes()
        );

        // The result is a normal transferable secret key.
        let armor = key.to_armored_string().unwrap();
        let (parsed, _) = SignedSecretKey::from_string(&armor).unwrap();
        parsed.verify().unwrap();
    }

    #[test]
    fn appended_signing_subkey_is_cross_certified() {
        let mut key = VanitySecretKey::from_existing(
            existing_key(),
            CipherSuite::Ed25519Sign,
            String::new(),
            thread_rng(),
        )
        .unwrap();
        assert_eq!(key.appended_target(), Some(KeyTarget::Sign));
        assert!(key.resolve_target(KeyTarget::Encrypt).is_err());

        key.edit_timestamp(1_700_000_000, thread_rng()).unwrap();

        let index = key.secret_key.secret_subkeys.len() - 1;
        let subkey = &key.secret_key.secret_subkeys[index];
        let binding = &subkey.signatures[0];
        assert!(binding.key_flags().sign());
        let back_signature = binding
            .embedded_signature()
            .expect("appended signing subkey is not cross-certified");

        binding
            .verify_key_binding(&key.secret_key, &subkey.key)
            .expect("invalid subkey binding signature");
        back_signature
            .verify_backwards_key_binding(&subkey.key, &key.secret_key)
            .expect("invalid primary key binding signature");
        assert_eq!(
            sha1_of_hashdata(&key, KeyTarget::Sign),
            subkey.fingerprint().as_bytes()
        );
    }

    #[test]
    fn new_candidates_change_the_subkey_material_only() {
        let key = VanitySecretKey::from_existing(
            existing_key(),
            CipherSuite::Cv25519,
            String::new(),
            thread_rng(),
        )
        .unwrap();
        let before = fingerprints(&key.secret_key);

        let candidate = key.new_candidate(1_650_000_000, thread_rng()).unwrap();
        let after = fingerprints(&candidate.secret_key);

        // The primary key and the imported subkeys keep their fingerprints.
        assert_eq!(&after[..before.len() - 1], &before[..before.len() - 1]);
        // A fresh subkey is generated for every candidate.
        assert_ne!(after[before.len() - 1], before[before.len() - 1]);

        let subkey = candidate.secret_key.secret_subkeys.last().unwrap();
        assert_eq!(subkey.created_at().timestamp(), 1_650_000_000);
        assert_eq!(
            sha1_of_hashdata(&candidate, KeyTarget::Encrypt),
            subkey.fingerprint().as_bytes()
        );
    }

    #[test]
    fn appending_rejects_primary_key_suites() {
        for suite in [
            CipherSuite::Ed25519,
            CipherSuite::EcdsaP256,
            CipherSuite::RSA2048,
        ] {
            assert!(
                VanitySecretKey::from_existing(existing_key(), suite, String::new(), thread_rng())
                    .is_err(),
                "{suite:?} should not be usable with --key-file"
            );
        }
    }

    #[test]
    fn appended_subkey_inherits_the_passphrase_protection() {
        let mut existing = existing_key();
        existing
            .primary_key
            .set_password(thread_rng(), || "correct horse".to_string())
            .unwrap();
        for subkey in &mut existing.secret_subkeys {
            subkey
                .key
                .set_password(thread_rng(), || "correct horse".to_string())
                .unwrap();
        }

        // A wrong passphrase is detected before the search starts.
        assert!(VanitySecretKey::from_existing(
            existing.clone(),
            CipherSuite::Cv25519,
            "wrong".into(),
            thread_rng()
        )
        .is_err());

        let mut key = VanitySecretKey::from_existing(
            existing,
            CipherSuite::Cv25519,
            "correct horse".into(),
            thread_rng(),
        )
        .unwrap();

        let index = key.secret_key.secret_subkeys.len() - 1;

        // Candidates stay unprotected while searching...
        key.edit_timestamp(1_600_000_000, thread_rng()).unwrap();
        assert!(matches!(
            key.secret_key.secret_subkeys[index].key.secret_params(),
            SecretParams::Plain(_)
        ));

        // ...and inherit the protection of the imported key once written out.
        key.protect_appended_subkey(thread_rng()).unwrap();
        assert!(matches!(
            key.secret_key.secret_subkeys[index].key.secret_params(),
            SecretParams::Encrypted(_)
        ));
        // Protecting twice is a no-op.
        key.protect_appended_subkey(thread_rng()).unwrap();

        let subkey = &key.secret_key.secret_subkeys[index];
        subkey.signatures[0]
            .verify_key_binding(&key.secret_key, &subkey.key)
            .unwrap();
        key.secret_key
            .primary_key
            .unlock(|| "correct horse".into(), |_| Ok(()))
            .unwrap();
        key.secret_key.secret_subkeys[index]
            .key
            .unlock(|| "correct horse".into(), |_| Ok(()))
            .unwrap();
    }

    #[test]
    fn load_secret_key_finds_the_key_by_fingerprint_suffix() {
        let key = existing_key();
        let armor = key.to_armored_string(pgp::ArmorOptions::default()).unwrap();
        let fingerprint = hex::encode_upper(key.fingerprint().as_bytes());

        let loaded = load_secret_key(armor.as_bytes(), None).unwrap();
        assert_eq!(
            loaded.fingerprint().as_bytes(),
            key.fingerprint().as_bytes()
        );

        let short_id = &fingerprint[fingerprint.len() - 16..];
        let loaded = load_secret_key(armor.as_bytes(), Some(short_id)).unwrap();
        assert_eq!(
            loaded.fingerprint().as_bytes(),
            key.fingerprint().as_bytes()
        );

        assert!(load_secret_key(armor.as_bytes(), Some("0000000000000000")).is_err());
        assert!(load_secret_key(armor.as_bytes(), Some("not hex")).is_err());
    }
}
