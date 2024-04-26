// Copyright (C) 2024 Edward Branch
// SPDX-License-Identifier: GPL-3.0-only

//! GnuPG cryptography helpers based on `gpgme`.
//!
//! Provides helper objects that also implement `db::MkCrypto` and `db::Crypto`
//! traits.

use super::db;

use anyhow::{Context, Error as AnyError, Result as AnyResult};
use gpgme::{error::Error as GpgError, Context as GpgContext, Protocol};

use std::path::PathBuf;

/// Builder for `Gpgh` that implements `db::MkCrypto`.
#[derive(Clone, Debug)]
pub struct MkGpgh {
    homedir: Option<PathBuf>,
    signer: Option<String>,
    flags: Vec<(String, String)>,
}

impl MkGpgh {
    /// Create new `MkGpgh` with given gpg homedir.
    pub fn new(homedir: Option<PathBuf>) -> Self {
        MkGpgh { homedir, signer: None, flags: Vec::default() }
    }
    /// Set UID of signer that will be assigned to any created `Gpgh`.
    pub fn set_signer(mut self, signer: String) -> Self {
        self.signer = Some(signer);
        self
    }
    /// Add gpgme context flags to any created `Gpgh` context.
    pub fn add_flag(mut self, key: &str, val: &str) -> Self {
        self.flags.push((key.to_string(), val.to_string()));
        self
    }
    /// Create a `Gpgh` object, propagating current settings.
    pub fn mk_gpgh(&self) -> AnyResult<Gpgh> {
        let mut ctx = GpgContext::from_protocol(Protocol::OpenPgp)
            .context("creating context")?;
        ctx.set_offline(true);
        if let Some(h) = &self.homedir {
            ctx.set_engine_home_dir(h.display().to_string())
                .context("setting homedir")?;
        }
        for (k, v) in self.flags.iter() {
            ctx.set_flag(k, v).with_context(|| {
                format!("setting context flag {k:?} = {v:?}")
            })?;
        }
        if let Some(s) = &self.signer {
            let k = get_key_can_sign(&mut ctx, s)?;
            ctx.add_signer(&k).context("adding signer key")?;
        }
        Ok(Gpgh::from(ctx))
    }
}

impl db::MkCrypto for MkGpgh {
    fn mk_crypto(&self) -> AnyResult<impl db::Crypto> {
        self.mk_gpgh()
    }
}

/// A gpgme::Context wrapper/helper that implements `db::Crypto`.
pub struct Gpgh {
    ctx: GpgContext,
    recips: Vec<gpgme::Key>,
}

impl Gpgh {
    /// gpgme encrypt wrapper that errors out if any recipients were invalid.
    pub fn encrypt_data<'p, 'c, P, C>(
        &mut self, plaintext: P, ciphertext: C,
    ) -> AnyResult<()>
    where
        P: gpgme::IntoData<'p>,
        C: gpgme::IntoData<'c>,
    {
        let res = self.ctx.encrypt(&self.recips, plaintext, ciphertext)?;
        if let Some(e) = handle_invalid_keys(res.invalid_recipients()) {
            Err(e)?
        }
        Ok(())
    }

    /// gpgme decrypt wrapper, no special behavior, just here for completeness.
    pub fn decrypt_data<'p, 'c, P, C>(
        &mut self, ciphertext: C, plaintext: P,
    ) -> AnyResult<()>
    where
        P: gpgme::IntoData<'p>,
        C: gpgme::IntoData<'c>,
    {
        self.ctx.decrypt(ciphertext, plaintext)?;
        Ok(())
    }

    /// gpgme `sign_and_encrypt` wrapper, erros if any keys are invalid.
    pub fn sign_and_encrypt_data<'p, 'c, P, C>(
        &mut self, plaintext: P, ciphertext: C,
    ) -> AnyResult<()>
    where
        P: gpgme::IntoData<'p>,
        C: gpgme::IntoData<'c>,
    {
        let res =
            self.ctx.sign_and_encrypt(&self.recips, plaintext, ciphertext)?;
        if let Some(e) = handle_sign_encrypt_res(&res) {
            Err(e)?
        }
        Ok(())
    }

    /// gpgme `decrypt_and_verify` wrapper, returns summary of verify result.
    pub fn decrypt_and_verify_data<'p, 'c, P, C>(
        &mut self, ciphertext: C, plaintext: P,
    ) -> AnyResult<String>
    where
        P: gpgme::IntoData<'p>,
        C: gpgme::IntoData<'c>,
    {
        let (_dc_res, vf_res) = self
            .ctx
            .decrypt_and_verify(ciphertext, plaintext)
            .context("decrypt and verify")?;
        Ok(display_verify(&mut self.ctx, vf_res))
    }
}

impl db::Crypto for Gpgh {
    fn encrypt(&mut self, data: &[u8]) -> AnyResult<Vec<u8>> {
        let mut out = Vec::<u8>::new();
        self.encrypt_data(data, &mut out)?;
        Ok(out)
    }

    fn decrypt(&mut self, data: &[u8]) -> AnyResult<Vec<u8>> {
        let mut out = Vec::<u8>::new();
        self.decrypt_data(data, &mut out)?;
        Ok(out)
    }

    fn add_recipient(&mut self, recipient: &str) -> AnyResult<()> {
        let key = get_key_can_encrypt(&mut self.ctx, recipient)?;
        self.recips.push(key);
        Ok(())
    }
}

impl From<GpgContext> for Gpgh {
    fn from(ctx: GpgContext) -> Self {
        Self { ctx, recips: Vec::<gpgme::Key>::new() }
    }
}

/// Tranlate any invalid recipients or signers into a single chained Error.
pub fn handle_sign_encrypt_res(
    res: &(gpgme::EncryptionResult, gpgme::SigningResult),
) -> Option<AnyError> {
    handle_invalid_keys(res.1.invalid_signers())?;
    handle_invalid_keys(res.0.invalid_recipients())
}

/// Tranlate any invalid keys into a single chained Error.
pub fn handle_invalid_keys<'a>(
    inv_keys: impl Iterator<Item = gpgme::InvalidKey<'a>>,
) -> Option<AnyError> {
    inv_keys
        .map(|inv_key: gpgme::InvalidKey<'a>| handle_invalid_key(&inv_key))
        .reduce(|accm, e| accm.context(e))
}

/// Tranlate an invalid key into an Error.
pub fn handle_invalid_key(inv_key: &gpgme::InvalidKey) -> AnyError {
    let msg = inv_key
        .fingerprint()
        .unwrap_or("<missing on invalid fingerprint>")
        .to_string();
    match inv_key.reason() {
        Some(e) => AnyError::new(e).context(msg),
        None => AnyError::msg(msg),
    }
}

/// Get a single key that is likely to succeed for signing.
pub fn get_key_can_sign(
    ctx: &mut GpgContext, uid: &str,
) -> AnyResult<gpgme::Key> {
    get_key(ctx, uid, |k| k.can_sign() && !k.is_bad())
        .with_context(|| format!("finding key {uid:?} for signing"))
}

/// Get a single key that is likely to succeed for encrypting.
pub fn get_key_can_encrypt(
    ctx: &mut GpgContext, uid: &str,
) -> AnyResult<gpgme::Key> {
    get_key(ctx, uid, |k| k.can_encrypt() && !k.is_bad())
        .with_context(|| format!("finding key {uid:?} for encrypting"))
}

/// Get a single key that is likely to succeed for encrypting and signing.
pub fn get_key_can_sign_and_encrypt(
    ctx: &mut GpgContext, uid: &str,
) -> AnyResult<gpgme::Key> {
    get_key(ctx, uid, |k| k.can_sign() && k.can_encrypt() && !k.is_bad())
        .with_context(|| format!("finding key {uid:?} for sign and encrypt"))
}

/// Get a single key that passes a predicate.
///
/// Unlike `gpgme::get_key`, this function filters based on the predicate
/// *prior* to ensuring only one match, so if the `uid` is ambiguous but
/// all but one matching keys fail the predicate then we successfully return
/// the single passing key.
pub fn get_key<F: Fn(&gpgme::Key) -> bool>(
    ctx: &mut GpgContext, uid: &str, filt: F,
) -> AnyResult<gpgme::Key> {
    Ok(ctx
        .find_keys([uid])?
        .filter(|r| match r {
            Ok(k) => filt(k),
            Err(_) => true,
        })
        .take(2)
        .reduce(|_accm, _r| Err(GpgError::AMBIGUOUS_NAME))
        .unwrap_or(Err(GpgError::EOF))?)
}

/// Format a verify result with a summary of each signature.
pub fn display_verify(
    ctx: &mut gpgme::Context, vfy_res: gpgme::VerificationResult,
) -> String {
    vfy_res
        .signatures()
        .fold(None::<String>, |accm, s| match accm {
            Some(a) => Some(format!("{a}\n{}", display_sig(ctx, &s))),
            None => Some(display_sig(ctx, &s)),
        })
        .unwrap_or("Verify: No signatures found.".to_string())
}

/// Get signer UID from a signature.
///
/// Since the Signature `key` is usually not filled in, we find the key by
/// fingerprint to get a UID.
pub fn uid_from_sig(
    ctx: &mut gpgme::Context, sig: &gpgme::Signature,
) -> AnyResult<String> {
    let fpr = match sig.fingerprint() {
        Ok(fpr) => fpr,
        Err(None) => Err(AnyError::msg("fingerprint unavailable"))?,
        Err(Some(e)) => Err(e).context("decoding fingerprint")?,
    };
    let key =
        ctx.get_key(fpr).with_context(|| format!("getting key for {fpr:?}"))?;
    Ok(match key.user_ids().next() {
        Some(uid) => uid.to_string(),
        None => fpr.to_string(),
    })
}

/// Format a summary of a signature.
pub fn display_sig(ctx: &mut gpgme::Context, sig: &gpgme::Signature) -> String {
    let uid_str =
        uid_from_sig(ctx, sig).unwrap_or_else(|e| format!("<Error: {e:#}>"));
    let summary = "Signature \"".to_string()
        + &uid_str
        + "\" "
        + if sig.summary().contains(gpgme::SignatureSummary::VALID) {
            "Valid"
        } else if sig.summary().contains(gpgme::SignatureSummary::GREEN) {
            "Ok"
        } else {
            "Invalid"
        };
    match sig.status() {
        Ok(_) => summary,
        Err(e) => format!("{summary}: {e}"),
    }
}

/// Format a signing result.
pub fn display_signing(sgn_res: &gpgme::SigningResult) -> String {
    sgn_res
        .new_signatures()
        .map(|new_sig| display_new_sig(&new_sig))
        .chain(
            sgn_res
                .invalid_signers()
                .map(|inv_key| display_invalid_key(&inv_key)),
        )
        .fold(None::<String>, |accm, s| match accm {
            Some(a) => Some(format!("{a}\n{s}")),
            None => Some(s),
        })
        .unwrap_or("Sign: No signatures added.".to_string())
}

/// Format a summary of a single invalid key.
pub fn display_invalid_key(inv_key: &gpgme::InvalidKey) -> String {
    let summary = "Failed to sign with ".to_string()
        + &display_fingerprint_result(&inv_key.fingerprint());
    match inv_key.reason() {
        Some(e) => format!("{summary}: {e}"),
        None => summary,
    }
}

/// Format summary of a new signature.
pub fn display_new_sig(sig: &gpgme::NewSignature) -> String {
    "Signed with ".to_string() + &display_fingerprint_result(&sig.fingerprint())
}

/// Format a summary of a fingerprint field.
pub fn display_fingerprint_result(
    fp: &Result<&str, Option<std::str::Utf8Error>>,
) -> String {
    match fp {
        Ok(f) => f.to_string(),
        Err(Some(e)) => format!("<Error: {e}>"),
        Err(None) => "<Error: no Id>".to_string(),
    }
}

//-----------------------------------------------------------------------------
// Test
//-----------------------------------------------------------------------------
#[cfg(test)]
#[path = "../test-common/test_env.rs"]
pub mod test_env;

#[cfg(test)]
mod tests {
    use super::test_env::*;
    use super::*;
    use db::Crypto;

    use sealed_test::prelude::*;

    fn new_mk_gpgh() -> MkGpgh {
        MkGpgh::new(Some(gpg_homedir()))
            .set_signer(TEST_UID.to_string())
            .add_flag("no-auto-check-trustdb", "1")
            .add_flag("trust-model", "always")
    }

    #[sealed_test(before = gpg_setup(), after = gpg_teardown())]
    fn setup_basic() {
        let mut gpgh = new_mk_gpgh().mk_gpgh().unwrap();
        get_key_can_sign_and_encrypt(&mut gpgh.ctx, TEST_UID).unwrap();
    }

    #[sealed_test(before = gpg_setup(), after = gpg_teardown())]
    fn encrypt_decrypt_roundtrip() {
        let ref_data = b"a very sensitive secret indeed".as_slice();
        let mut gpgh = new_mk_gpgh().mk_gpgh().unwrap();
        gpgh.add_recipient(TEST_UID).unwrap();
        let mut encrypted = Vec::<u8>::new();
        let mut decrypted = Vec::<u8>::new();
        gpgh.sign_and_encrypt_data(ref_data, &mut encrypted).unwrap();
        assert!(encrypted != ref_data);
        gpgh.decrypt_and_verify_data(&encrypted, &mut decrypted).unwrap();
        assert_eq!(decrypted, ref_data);
    }
}
