//! DSSE (Dead Simple Signing Envelope) for attestation authenticity.
//!
//! Wraps attestations in signed envelopes so a third party can verify
//! who produced an attestation without re-executing the build.
//!
//! The payload is the attestation JSON; payload type matches the
//! predicate URI so verifiers can dispatch on version.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// DSSE pre-authenticated encoding version prefix.
const PAE_PREFIX: &[u8] = b"DSSEv1";

// ---------------------------------------------------------------------------
// DSSE types
// ---------------------------------------------------------------------------

/// A DSSE envelope carrying a signed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,

    /// Base64-encoded payload (the attestation JSON).
    pub payload: String,

    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Empty string or base64-encoded public key fingerprint.
    #[serde(default)]
    pub keyid: String,

    /// Base64-encoded Ed25519 signature over PAE(payloadType, payload).
    pub sig: String,
}

// ---------------------------------------------------------------------------
// Pre-Authenticated Encoding (PAE)
// ---------------------------------------------------------------------------
//
// PAE prevents cross-protocol signature confusion by binding the
// signature to both the payload type and the payload bytes.
//
// Format:
//   DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
//
// The three-character separators are exactly "<space><digit><space>".

/// Compute the DSSE pre-authenticated encoding for `payload_type` + `payload`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(PAE_PREFIX.len() + 4 + payload_type.len() + 4 + payload.len());
    buf.extend_from_slice(PAE_PREFIX);
    buf.push(b' ');
    buf.extend_from_slice(payload_type.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload_type.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/// Sign a payload and return a DSSE envelope.
pub fn sign(payload: &[u8], payload_type: &str, signing_key: &SigningKey) -> Envelope {
    let pae_bytes = pae(payload_type, payload);
    let signature = signing_key.sign(&pae_bytes);

    Envelope {
        payload_type: payload_type.to_string(),
        payload: BASE64.encode(payload),
        signatures: vec![DsseSignature {
            keyid: String::new(),
            sig: BASE64.encode(signature.to_bytes()),
        }],
    }
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify one DSSE signature against a known verifying key.
///
/// Returns the decoded payload bytes on success so callers can
/// deserialize and validate the attestation without re-decoding.
pub fn verify(envelope: &Envelope, verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    let payload = BASE64
        .decode(&envelope.payload)
        .context("invalid base64 in DSSE payload")?;

    let pae_bytes = pae(&envelope.payload_type, &payload);

    if envelope.signatures.is_empty() {
        bail!("DSSE envelope has no signatures");
    }

    let mut last_err: Option<anyhow::Error> = None;
    for (i, sig) in envelope.signatures.iter().enumerate() {
        let sig_bytes = match BASE64.decode(&sig.sig) {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(anyhow::anyhow!("signature {i}: invalid base64: {e}"));
                continue;
            }
        };
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(anyhow::anyhow!("signature {i}: invalid ed25519: {e}"));
                continue;
            }
        };
        match verifying_key.verify(&pae_bytes, &signature) {
            Ok(()) => return Ok(payload),
            Err(e) => {
                last_err = Some(anyhow::anyhow!("signature {i}: verification failed: {e}"));
                continue;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no valid signature found")))
}

// ---------------------------------------------------------------------------
// Key I/O helpers — raw 32-byte keys, hex-encoded
// ---------------------------------------------------------------------------

/// Parse a hex-encoded Ed25519 signing key (32-byte seed).
pub fn parse_signing_key(hex: &str) -> Result<SigningKey> {
    let hex = hex.trim();
    let bytes = hex::decode(hex).context("signing key is not valid hex")?;
    if bytes.len() != 32 {
        bail!(
            "signing key must be 32 bytes ({} hex chars), got {} bytes",
            64,
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

/// Parse a hex-encoded Ed25519 verifying key (32-byte public key).
pub fn parse_verifying_key(hex: &str) -> Result<VerifyingKey> {
    let hex = hex.trim();
    let bytes = hex::decode(hex).context("verifying key is not valid hex")?;
    if bytes.len() != 32 {
        bail!(
            "verifying key must be 32 bytes ({} hex chars), got {} bytes",
            64,
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).context("invalid ed25519 verifying key")
}

/// Read a signing key from a file.
///
/// The file must contain a hex-encoded 32-byte seed.  Leading/trailing
/// whitespace is stripped.
pub fn read_signing_key(path: &std::path::Path) -> Result<SigningKey> {
    let hex = std::fs::read_to_string(path)
        .with_context(|| format!("reading signing key from {}", path.display()))?;
    parse_signing_key(&hex)
}

/// Read a verifying key from a file.
pub fn read_verifying_key(path: &std::path::Path) -> Result<VerifyingKey> {
    let hex = std::fs::read_to_string(path)
        .with_context(|| format!("reading verifying key from {}", path.display()))?;
    parse_verifying_key(&hex)
}

/// Write a signing key to a file (owner-readable only on Unix).
pub fn write_signing_key(path: &std::path::Path, key: &SigningKey) -> Result<()> {
    let hex = hex::encode(key.to_bytes());
    std::fs::write(path, format!("{hex}\n"))
        .with_context(|| format!("writing signing key to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .with_context(|| format!("stat'ing {}", path.display()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

/// Write a verifying key to a file.
pub fn write_verifying_key(path: &std::path::Path, key: &VerifyingKey) -> Result<()> {
    let hex = hex::encode(key.to_bytes());
    std::fs::write(path, format!("{hex}\n"))
        .with_context(|| format!("writing verifying key to {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Key generation for testing
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 key pair.
pub fn generate_key_pair() -> (SigningKey, VerifyingKey) {
    use rand::Rng;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_round_trips() {
        let payload_type = "https://repx.dev/process-provenance/v0.3.0";
        let payload = br#"{"version":"0.3.0"}"#;

        let encoded = pae(payload_type, payload);
        // PAE must be deterministic.
        let encoded2 = pae(payload_type, payload);
        assert_eq!(encoded, encoded2);

        // PAE must differ when payload type changes.
        let encoded_other_type = pae("other", payload);
        assert_ne!(encoded, encoded_other_type);

        // PAE must differ when payload bytes change.
        let encoded_other_payload = pae(payload_type, b"other");
        assert_ne!(encoded, encoded_other_payload);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (signing_key, verifying_key) = generate_key_pair();
        let payload_type = "https://repx.dev/process-provenance/v0.3.0";
        let payload = br#"{"version":"0.3.0","root_hash":"sha256:test"}"#;

        let envelope = sign(payload, payload_type, &signing_key);
        let decoded = verify(&envelope, &verifying_key).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (signing_key, _) = generate_key_pair();
        let (_, wrong_verifying_key) = generate_key_pair();

        let envelope = sign(b"data", "type", &signing_key);
        assert!(verify(&envelope, &wrong_verifying_key).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected_by_verify() {
        let (signing_key, verifying_key) = generate_key_pair();
        let mut envelope = sign(b"original", "type", &signing_key);
        envelope.payload = BASE64.encode(b"tampered");
        assert!(verify(&envelope, &verifying_key).is_err());
    }

    #[test]
    fn empty_signatures_is_rejected() {
        let (_, verifying_key) = generate_key_pair();
        let envelope = Envelope {
            payload_type: "type".into(),
            payload: BASE64.encode(b"data"),
            signatures: vec![],
        };
        assert!(verify(&envelope, &verifying_key).is_err());
    }

    #[test]
    fn key_hex_round_trip() {
        let (signing_key, verifying_key) = generate_key_pair();

        let signing_hex = hex::encode(signing_key.to_bytes());
        let parsed_signing = parse_signing_key(&signing_hex).unwrap();
        assert_eq!(
            signing_key.to_bytes(),
            parsed_signing.to_bytes()
        );

        let verifying_hex = hex::encode(verifying_key.to_bytes());
        let parsed_verifying = parse_verifying_key(&verifying_hex).unwrap();
        assert_eq!(
            verifying_key.to_bytes(),
            parsed_verifying.to_bytes()
        );
    }

    #[test]
    fn signing_key_rejects_wrong_length() {
        assert!(parse_signing_key("deadbeef").is_err());
        assert!(parse_signing_key("").is_err());
    }

    #[test]
    fn envelope_json_round_trip() {
        let (signing_key, _) = generate_key_pair();
        let envelope = sign(b"test payload", "test-type", &signing_key);

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();

        assert_eq!(envelope.payload_type, parsed.payload_type);
        assert_eq!(envelope.payload, parsed.payload);
        assert_eq!(envelope.signatures.len(), parsed.signatures.len());
        assert_eq!(envelope.signatures[0].sig, parsed.signatures[0].sig);
    }

    #[test]
    fn full_attestation_sign_and_verify() {
        // Build a real attestation, sign it, verify the signature, and
        // validate the attestation from the verified payload.
        use crate::attestation::{Attestation, OutputSelection};
        use crate::merkle;

        let tree = merkle::MerkleTree {
            leaves: vec!["sha256:operation".to_string()],
            nodes: Vec::new(),
            leaf_count: 1,
        };
        let att = Attestation::new_with_outputs(
            tree,
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        let payload = serde_json::to_vec(&att).unwrap();

        let (signing_key, verifying_key) = generate_key_pair();
        let envelope = sign(&payload, &att.predicate_type, &signing_key);

        // Round-trip through JSON (simulates file I/O).
        let envelope_json = serde_json::to_vec(&envelope).unwrap();
        let parsed_envelope: Envelope = serde_json::from_slice(&envelope_json).unwrap();

        let verified_payload = verify(&parsed_envelope, &verifying_key).unwrap();
        assert_eq!(verified_payload, payload);

        let mut verified_att: Attestation =
            serde_json::from_slice(&verified_payload).unwrap();
        verified_att.validate().unwrap();
        assert_eq!(verified_att.root_hash, att.root_hash);
    }
}
