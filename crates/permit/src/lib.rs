use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolValue;
use k256::ecdsa::{SigningKey, VerifyingKey};

#[derive(Debug, Clone)]
pub struct RiskPermit {
    pub user_op_hash: B256,
    pub chain_id: U256,
    pub entry_point: Address,
    pub policy_root: B256,
    pub valid_until: u64,
}

impl RiskPermit {
    pub fn digest(&self) -> B256 {
        let encoded = (
            self.user_op_hash,
            self.chain_id,
            self.entry_point,
            self.policy_root,
            self.valid_until,
        )
            .abi_encode();
        keccak256(encoded)
    }
}

pub struct PermitSigner {
    signing_key: SigningKey,
}

impl PermitSigner {
    pub fn new(private_key_bytes: [u8; 32]) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from_bytes(&private_key_bytes.into())
            .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;
        Ok(Self { signing_key })
    }

    /// Sign a RiskPermit.
    ///
    /// `permit.digest()` is already a single keccak256 hash (32 bytes).
    /// We sign it directly as a raw prehash — no additional hashing.
    /// This matches Solidity's ECDSA.recover which treats the input as the
    /// raw signed hash.
    pub fn sign(&self, permit: &RiskPermit) -> anyhow::Result<Bytes> {
        let digest = permit.digest();
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(digest.as_slice())
            .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
        let mut v = [0u8; 65];
        v[..32].copy_from_slice(&sig.r().to_bytes());
        v[32..64].copy_from_slice(&sig.s().to_bytes());
        v[64] = recid.to_byte() + 27;
        Ok(Bytes::from(v.to_vec()))
    }

    pub fn public_address(&self) -> Address {
        let verifying_key: &VerifyingKey = self.signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false);
        let uncompressed = public_key.as_bytes();
        let hash = keccak256(&uncompressed[1..]);
        Address::from_slice(&hash[12..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::RecoveryId;

    fn pubkey_to_address(key: &VerifyingKey) -> Address {
        let point = key.to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        Address::from_slice(&hash[12..])
    }

    fn test_signer() -> PermitSigner {
        PermitSigner::new([0xab; 32]).unwrap()
    }

    fn test_permit() -> RiskPermit {
        RiskPermit {
            user_op_hash: B256::repeat_byte(0x11),
            chain_id: U256::from(1),
            entry_point: Address::repeat_byte(0x22),
            policy_root: B256::repeat_byte(0x33),
            valid_until: 1_700_000_000,
        }
    }

    #[test]
    fn sign_returns_65_bytes() {
        let sig = test_signer().sign(&test_permit()).unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn public_address_is_deterministic() {
        let s = test_signer();
        let a1 = s.public_address();
        let a2 = s.public_address();
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_permit_different_signature() {
        let signer = test_signer();
        let p1 = test_permit();
        let mut p2 = test_permit();
        p2.valid_until = p1.valid_until + 1;
        let s1 = signer.sign(&p1).unwrap();
        let s2 = signer.sign(&p2).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn digest_differs_for_different_chain_ids() {
        let p1 = test_permit();
        let mut p2 = test_permit();
        p2.chain_id = U256::from(137);
        assert_ne!(p1.digest(), p2.digest());
    }

    #[test]
    fn recovered_address_matches_public_address() {
        let signer = test_signer();
        let expected = signer.public_address();
        let permit = test_permit();
        let sig_bytes = signer.sign(&permit).unwrap();

        let r = <[u8; 32]>::try_from(&sig_bytes[..32]).unwrap();
        let s = <[u8; 32]>::try_from(&sig_bytes[32..64]).unwrap();
        let v = sig_bytes[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28, got {v}");

        let recid = RecoveryId::try_from(v - 27).unwrap();
        let signature = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        let digest = permit.digest();

        // Recover using sign_prehash_recoverable's counterpart:
        // recover_from_prehash signs zero additional hashing.
        let recovered_key =
            VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recid)
                .expect("recovery should succeed");

        let recovered_pub = recovered_key.to_encoded_point(false);
        let recovered_hash = keccak256(&recovered_pub.as_bytes()[1..]);
        let recovered_addr = Address::from_slice(&recovered_hash[12..]);
        assert_eq!(recovered_addr, expected);
    }

    /// Definitive proof test: sign() signs permit.digest() DIRECTLY (single
    /// keccak256), NOT keccak256(permit.digest()) (double hash).
    ///
    /// We sign with sign_prehash_recoverable (no additional hashing), then
    /// recover against both the raw digest and a double-hashed version.
    /// Only the raw digest recovery yields the correct signer address.
    #[test]
    fn signs_single_hash_not_double_hash() {
        let signer = test_signer();
        let expected_addr = signer.public_address();
        let permit = test_permit();
        let digest = permit.digest();
        let sig_bytes = signer.sign(&permit).unwrap();

        let r = <[u8; 32]>::try_from(&sig_bytes[..32]).unwrap();
        let s = <[u8; 32]>::try_from(&sig_bytes[32..64]).unwrap();
        let v = sig_bytes[64];
        let recid = RecoveryId::try_from(v - 27).unwrap();
        let signature = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        // Recover against the raw digest (single keccak256) — MUST yield
        // the correct signer address.
        let key_raw =
            VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recid).unwrap();
        let addr_raw = pubkey_to_address(&key_raw);
        assert_eq!(
            addr_raw, expected_addr,
            "raw digest recovery must match signer address"
        );

        // Recover against keccak256(digest) (double hash) — yields a
        // DIFFERENT address, proving sign() does NOT double-hash.
        let double_hash = keccak256(digest.as_slice());
        let key_double =
            VerifyingKey::recover_from_prehash(double_hash.as_slice(), &signature, recid).unwrap();
        let addr_double = pubkey_to_address(&key_double);
        assert_ne!(
            addr_double, expected_addr,
            "double-hash recovery must NOT match signer — sign() signs single hash"
        );
    }
}
