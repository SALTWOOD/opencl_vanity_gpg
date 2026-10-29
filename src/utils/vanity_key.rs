use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use chrono::SubsecRound;
use log::{debug, info};
use pgp::{
    composed::{key::SecretKeyParamsBuilder, KeyType},
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{KeyFlags, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize,
    types::{CompressionAlgorithm, KeyVersion, PublicKeyTrait, SecretKeyTrait},
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
/// explicitly.
fn create_key_binding_signature(
    config: SignatureConfig,
    signer: &impl SecretKeyTrait,
    primary: &impl PublicKeyTrait,
    subkey: &impl PublicKeyTrait,
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
    let signature = signer.create_signature(String::new, config.hash_alg, &hash)?;

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
    let back_signature = create_key_binding_signature(back_config, subkey, primary_key, subkey)?;

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

    create_key_binding_signature(binding_config, primary_key, primary_key, subkey)
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
        )?];
    }

    Ok(())
}

pub struct VanitySecretKey {
    pub secret_key: SignedSecretKey,
    /// Key flags of the subkeys, in the same order as `secret_key.secret_subkeys`.
    /// The crate does not expose them after generation, so keep our own copy to
    /// re-sign the key without changing the intended capabilities.
    subkey_flags: Vec<KeyFlags>,
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
        }
    }

    pub fn edit_timestamp(&mut self, timestamp: u32, mut rng: impl Rng + CryptoRng) {
        // RFC 9580 - OpenPGP
        // 4. Packet Syntax
        // https://datatracker.ietf.org/doc/html/rfc9580#name-packet-syntax
        let mut secret_key_bytes = self.secret_key.to_bytes().unwrap();
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
        let edited_key = SignedSecretKey::from_bytes(&secret_key_bytes[..]).unwrap();

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
        .sign(&mut rng, String::new)
        .unwrap();
        cross_certify_signing_subkeys(&mut re_signed_key, &subkey_flags).unwrap();
        self.secret_key = re_signed_key;
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
    }
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
        key.edit_timestamp(1_600_000_000, thread_rng());

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
            key.edit_timestamp(1_600_000_000, thread_rng());

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
}
