//! Cryptographic keys

use self::ed25519::Ed25519Scheme;
use self::sigscheme::SigScheme;
use super::address::Address;
use super::storage::{self, DbKeySeg, Key, KeySeg};

pub mod ed25519;
pub mod sigscheme;

/// The signing scheme implementations
#[derive(Debug, Clone)]
pub enum Scheme {
    Ed25519,
}

/// Public key
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
}

/// Secret key
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum SecretKey {
    Ed25519(ed25519::SecretKey),
}

/// Signature
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum Signature {
    Ed25519(ed25519::Signature),
}

/// Keypair
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Keypair {
    Ed25519(ed25519::Keypair),
}

#[allow(missing_docs)]
#[derive(Error)]
pub enum VerifyError {}

pub struct Common;

const PK_STORAGE_KEY: &str = "public_key";

/// Obtain a storage key for user's public key.
pub fn pk_key(owner: &Address) -> storage::Key {
    Key::from(owner.to_db_key())
        .push(&PK_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_pk_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key == PK_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

const KEYPAIR_LENGTH: usize;

pub fn generate<R>(csprng: &mut R, scheme: Scheme) -> Keypair
where
    R: rand::CryptoRng + rand::RngCore,
{
    match scheme {
        Scheme::Ed25519 => Keypair::Ed25519(Ed25519Scheme::generate(csprng)),
    }
}

fn sign(keypair: &Keypair, data: impl AsRef<[u8]>) -> Signature {
    match keypair {
        Keypair::Ed25519(keypair) => {
            Signature::Ed25519(Ed25519Scheme::sign(keypair, data))
        }
    }
}

fn verify_signature<T: borsh::BorshSerialize + borsh::BorshDeserialize>(
    pk: &PublicKey,
    data: &T,
    sig: &Signature,
) -> Result<(), VerifyError> {
    match (pk, sig) {
        (PublicKey::Ed25519(pk), Signature::Ed25519(sig)) => {
            Ed25519Scheme::verify_signature(pk, data, sig)
        } /*  _ => {
           *      Error::MismatchedScheme
           *  } */
    }
}

fn verify_signature_raw(
    pk: &PublicKey,
    data: &[u8],
    sig: &Signature,
) -> Result<(), VerifyError> {
    match (pk, sig) {
        (PublicKey::Ed25519(pk), Signature::Ed25519(sig)) => {
            Ed25519Scheme::verify_signature_raw(pk, data, sig)
        } /*  _ => {
           *      Error::MismatchedScheme
           *  } */
    }
}

fn sign_tx(keypair: &Keypair, tx: crate::proto::Tx) -> crate::proto::Tx {
    match keypair {
        Keypair::Ed25519(keypair) => Ed25519Scheme::sign_tx(keypair, tx),
    }
}

fn verify_tx_sig(
    pk: &PublicKey,
    tx: &crate::proto::Tx,
    sig: &Signature,
) -> Result<(), VerifyError> {
    match (pk, sig) {
        (PublicKey::Ed25519(pk), Signature::Ed25519(sig)) => {
            SigScheme::verify_tx_sig(pk, tx, sig)
        } /*  _ => {
           *      Error::MismatchedScheme
           *  } */
    }
}
