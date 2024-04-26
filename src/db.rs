// Copyright (C) 2024 Edward Branch
// SPDX-License-Identifier: GPL-3.0-only

//! Application database wrapper of all records, tags, and other metadata.
//!
//! Wraps and provides a public interface to the application database. The
//! underlying database object is auto-generated from the Protobuf IDL.

use super::pb::pwdb as pb;

use anyhow::{Context, Error as AnyError, Result as AnyResult};
use protobuf::Message;

//-----------------------------------------------------------------------------
// Error
//-----------------------------------------------------------------------------

/// Error type for all errors used by this module.
#[derive(Debug)]
pub enum Error {
    RecordExists(String),
    NoSuchRecord(String),
    TagExists(String),
    NoSuchTag(String),
    RecordHasTag(String, String),
    RecordDoesNotHaveTag(String, String),
    Other(AnyError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RecordExists(rcd) => write!(f, "Record {rcd:?} already exists"),
            NoSuchRecord(rcd) => write!(f, "No such record {rcd:?}"),
            TagExists(tag) => write!(f, "Tag {tag:?} already exists"),
            NoSuchTag(tag) => write!(f, "No such tag {tag:?}"),
            RecordHasTag(rcd, tag) => {
                write!(f, "Record {rcd:?} already has tag {tag:?}")
            }
            RecordDoesNotHaveTag(rcd, tag) => {
                write!(f, "Record {rcd:?} does not have tag {tag:?}")
            }
            Other(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Other(e) => e.source(),
            _ => None,
        }
    }
}

impl From<AnyError> for Error {
    fn from(e: AnyError) -> Self {
        Self::Other(e)
    }
}

/// Result type for Error
pub type Result<T> = ::std::result::Result<T, Error>;
use Error::*;

//-----------------------------------------------------------------------------
// Cryptography support
//-----------------------------------------------------------------------------

/// Interface for the cryptography operations required by this module.
///
/// An obejct implementing this trait must be externally provided.
pub trait Crypto {
    fn encrypt(&mut self, data: &[u8]) -> AnyResult<Vec<u8>>;
    fn decrypt(&mut self, data: &[u8]) -> AnyResult<Vec<u8>>;
    fn add_recipient(&mut self, recipient: &str) -> AnyResult<()>;

    /// Add recipients to the Crypto object.
    ///
    /// This funciton is pro-active, not lazy. Upon return, `add_recipient` has
    /// been called for each item in `recipients`. A `Result` is returned for
    /// each recipient attempted.
    fn add_recipients<'a>(
        &mut self, recipients: impl IntoIterator<Item = &'a str>,
    ) -> impl Iterator<Item = AnyResult<()>> {
        // Note: collect() in this chain is to make the function pro-active.
        recipients
            .into_iter()
            .map(|r| self.add_recipient(r))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Add recipients to the Crypto object, returning a single `Result`.
    ///
    /// Attempts to add all recipients regardless of prior errors, but folds
    /// all errors into a single `Error` chain.
    fn add_recipients_fold<'a>(
        &mut self, recipients: impl IntoIterator<Item = &'a str>,
    ) -> AnyResult<()> {
        recipients
            .into_iter()
            .map(|r| self.add_recipient(r))
            .reduce(|accm, r| match (accm, r) {
                (Ok(_), Ok(_)) => Ok(()),
                (Ok(_), Err(re)) => Err(re),
                (Err(ae), Ok(_)) => Err(ae),
                (Err(ae), Err(re)) => Err(ae.context(re)),
            })
            .unwrap_or(Ok(()))
    }
}

/// Interface for creating a `Crypto` object.
///
/// An obejct implementing this trait must be externally provided. This allows
/// `Crypto` objects to be created on demand, since they are not always
/// re-usable.
pub trait MkCrypto {
    fn mk_crypto(&self) -> AnyResult<impl Crypto>;
}

//-----------------------------------------------------------------------------
// Utility
//-----------------------------------------------------------------------------

// Remove all elements of v that are equal to eq.
// Returns number of elements removed.
fn vec_purge_eq<T: std::cmp::PartialEq>(v: &mut Vec<T>, eq: &T) -> usize {
    let orig_len = v.len();
    v.retain(|x| x != eq);
    orig_len - v.len()
}

//-----------------------------------------------------------------------------
// pb::Store extension
//-----------------------------------------------------------------------------
impl pb::Store {
    /// Construct a Store from encrypted serialized data.
    pub fn decrypt<C: Crypto>(crypto: &mut C, data: &[u8]) -> AnyResult<Self> {
        let dec = crypto.decrypt(data).context("decrypting")?;
        pb::Store::parse_from_bytes(&dec).context("de-serializing")
    }

    /// Return the encrypted serialized representation of a Store.
    pub fn encrypt<C: Crypto>(&self, crypto: &mut C) -> AnyResult<Vec<u8>> {
        let ser = self.write_to_bytes().context("serializing")?;
        crypto.encrypt(&ser).context("encrypting")
    }
}

impl<const N: usize> From<[(&str, &str); N]> for pb::Store {
    fn from(arr: [(&str, &str); N]) -> Self {
        Self {
            values: arr
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Self::default()
        }
    }
}

//-----------------------------------------------------------------------------
// pb::Record extension
//-----------------------------------------------------------------------------
impl pb::Record {
    /// Get a referencing iterator over local recipients.
    pub fn ref_recipients(&self) -> impl Iterator<Item = &str> {
        self.recipient.iter().map(String::as_str)
    }
    /// Add record recipients to a Crypto object.
    ///
    /// Any valid recipients will be added to the Crypto regardless of the
    /// presence of other invalid recipients.
    pub fn add_recipients<C: Crypto>(&self, crypto: &mut C) -> AnyResult<()> {
        crypto.add_recipients_fold(self.ref_recipients())
    }
    /// Get the payload store, decrypting from Data if necessary.
    pub fn get_decrypt_store<C: Crypto>(
        &self, crypto: &mut C,
    ) -> AnyResult<pb::Store> {
        match &self.payload {
            Some(p) => match p {
                pb::record::Payload::Store(s) => Ok(s.clone()),
                pb::record::Payload::Data(d) => pb::Store::decrypt(crypto, d),
            },
            None => Ok(pb::Store::default()),
        }
    }
    /// Encrypt a Store and set the payload Data to it.
    ///
    /// Payload will be set to `None` if `store` is empty.
    ///
    /// On success, returns Ok(Some(AnyError)) if there were invalid
    /// recipients, ie. invalid record recipients is **not** an error; the
    /// operation "succeeds" if the encryption operation returns valid
    /// encrypted data.
    pub fn put_encrypt_store<C: Crypto>(
        &mut self, mut crypto: C, store: &pb::Store,
    ) -> AnyResult<Option<AnyError>> {
        let mut recips_err = None;
        self.payload = match store.values.is_empty() {
            true => None,
            false => {
                recips_err = self.add_recipients(&mut crypto).err();
                Some(pb::record::Payload::Data(store.encrypt(&mut crypto)?))
            }
        };
        Ok(recips_err)
    }
    /// Decrypt any payload Data, converting payload to a Store inplace.
    ///
    /// If payload is `None` it is left unmodified.
    pub fn decrypt_inplace<C: Crypto>(
        &mut self, crypto: &mut C,
    ) -> AnyResult<()> {
        if let Some(pb::record::Payload::Data(d)) = &self.payload {
            self.payload = Some(pb::record::Payload::Store(
                pb::Store::decrypt(crypto, d)?,
            ));
        }
        Ok(())
    }
    /// Encrypt any payload Store, converting payload to Data inplace.
    ///
    /// Payload will be `None` if it was `None` or an empty `Store`.
    ///
    /// On success, returns Ok(Some(AnyError)) if there were invalid
    /// recipients, ie. invalid record recipients is **not** an error; the
    /// operation "succeeds" if the encryption operation returns valid
    /// encrypted data.
    pub fn encrypt_inplace<C: Crypto>(
        &mut self, mut crypto: C,
    ) -> AnyResult<Option<AnyError>> {
        let mut recips_err = None;
        if let Some(pb::record::Payload::Store(s)) = &self.payload {
            self.payload = match s.values.is_empty() {
                true => None,
                false => {
                    recips_err = self.add_recipients(&mut crypto).err();
                    Some(pb::record::Payload::Data(s.encrypt(&mut crypto)?))
                }
            };
        }
        Ok(recips_err)
    }
}

//-----------------------------------------------------------------------------
/// The database of all records, tags, and other metadata.
///
/// Db is just a wrapper around the protobuf generated `pb::pwdb::DB` message
/// representation. The underlying struct is private to maintain the following
/// invariants:
/// * Tag list entries must refer to records that exist.
/// * Tag list entries must be unique within a list.
///
/// No invariant considers any content of the records, so they are exposed
/// directly. Because we expose the underlying `pb::pwdb::DB` as const (it's
/// safe WRT the invariants) no getter-like functions are necessary, although
/// some may be provided as a convenience.
//-----------------------------------------------------------------------------
#[derive(PartialEq, Clone, Default, Debug)]
pub struct Db {
    pdb: pb::DB,
}

impl Db {
    /// Create a new Db from a pb::DB protobuf message
    pub fn new(pdb: pb::DB) -> Db {
        Db { pdb }
    }
    /// Accessor for the underlying protobuf `pb::pwdb::DB` message.
    pub fn get_pdb(&self) -> &pb::DB {
        &self.pdb
    }
    /// Accessor for the UID used for PGP signing and default recipient.
    pub fn mut_uid(&mut self) -> &mut String {
        &mut self.pdb.uid
    }
    /// Add a new default record by name.
    ///
    /// Returns: A reference to the new record for modification.
    ///
    /// Errors: `RecordExists`
    pub fn new_rcd(&mut self, name: &str) -> Result<&mut pb::Record> {
        let mut added = false;
        let v = self.pdb.records.entry(name.to_string()).or_insert_with(|| {
            added = true;
            pb::Record::default()
        });
        added.then_some(v).ok_or(RecordExists(name.to_string()))
    }
    /// Remove a record by name.
    ///
    /// Returns: The Record that was removed.
    ///
    /// Errors: `NoSuchRecord`
    pub fn remove_rcd(&mut self, name: &str) -> Result<pb::Record> {
        let rcd = self
            .pdb
            .records
            .remove(name)
            .ok_or(NoSuchRecord(name.to_string()))?;
        for tv in self.pdb.tags.values_mut() {
            vec_purge_eq(&mut tv.str, &name.to_string());
        }
        Ok(rcd)
    }
    /// Access a record by name for modification.
    ///
    /// Errors: `NoSuchRecord`
    pub fn get_mut_rcd(&mut self, name: &str) -> Result<&mut pb::Record> {
        self.pdb.records.get_mut(name).ok_or(NoSuchRecord(name.to_string()))
    }
    /// Access a record by name.
    ///
    /// Errors: `NoSuchRecord`
    pub fn get_rcd(&self, name: &str) -> Result<&pb::Record> {
        self.pdb.records.get(name).ok_or(NoSuchRecord(name.to_string()))
    }
    /// Get all recipients over the entire Db.
    ///
    /// Includes the uid and the record-specific recipients of every record.
    pub fn get_all_recipients(&self) -> impl Iterator<Item = &str> {
        let mut accm = Vec::from([&self.pdb.uid]);
        for rcd in self.pdb.records.values() {
            accm.extend(&rcd.recipient);
        }
        accm.sort();
        accm.dedup();
        accm.into_iter().map(String::as_str)
    }
    /// Get record store, decrypting and deserializing if necessary.
    ///
    /// Errors: `NoSuchRecord`, `Other`
    pub fn get_decrypt_rcd_store<C: Crypto>(
        &self, crypto: &mut C, name: &str,
    ) -> Result<pb::Store> {
        Ok(self.get_rcd(name)?.get_decrypt_store(crypto)?)
    }
    /// Save a store in a record as serialized and encrypted data.
    ///
    /// Errors: `NoSuchRecord`, `Other`
    pub fn put_encrypt_rcd_store<C: Crypto>(
        &mut self, mut crypto: C, name: &str, store: &pb::Store,
    ) -> Result<Option<AnyError>> {
        crypto.add_recipient(self.pdb.uid.as_str())?;
        let rcd = self.get_mut_rcd(name)?;
        let inv_recips = rcd.put_encrypt_store(crypto, store)?;
        Ok(inv_recips
            .map(|e| e.context("record {name:?} has invalid recipients")))
    }
    /// Serialize and encrypt all un-encrypted records.
    ///
    /// Errors: `Other`
    pub fn encrypt_all_rcds<C: MkCrypto>(
        &mut self, mk_crypto: &C,
    ) -> Result<Vec<AnyError>> {
        let mut inv_recips = Vec::<AnyError>::new();
        for (name, rcd) in self.pdb.records.iter_mut() {
            let mut crypto = mk_crypto.mk_crypto()?;
            crypto.add_recipient(self.pdb.uid.as_str())?;
            if let Some(e) = rcd
                .encrypt_inplace(crypto)
                .with_context(|| format!("record {name:?}"))?
            {
                inv_recips.push(e);
            }
        }
        Ok(inv_recips)
    }
    /// Decrypt and deserialize all encrypted records.
    ///
    /// Errors: `Other`
    pub fn decrypt_all_rcds<C: MkCrypto>(
        &mut self, mk_crypto: &C,
    ) -> Result<()> {
        let mut crypto = mk_crypto.mk_crypto()?;
        for (name, rcd) in self.pdb.records.iter_mut() {
            rcd.decrypt_inplace(&mut crypto)
                .with_context(|| format!("record {name:?}"))?;
        }
        Ok(())
    }
    /// /[Re/]-encrypt all record payloads.
    ///
    /// Errors: `Other`
    pub fn recrypt_all_rcds<C: MkCrypto>(
        &mut self, mk_crypto: &C,
    ) -> Result<Vec<AnyError>> {
        let mut inv_recips = Vec::<AnyError>::new();
        for (name, rcd) in self.pdb.records.iter_mut() {
            let mut crypto = mk_crypto.mk_crypto()?;
            crypto.add_recipient(self.pdb.uid.as_str())?;
            rcd.decrypt_inplace(&mut crypto)
                .with_context(|| format!("record {name:?}"))?;
            if let Some(e) = rcd
                .encrypt_inplace(crypto)
                .with_context(|| format!("record {name:?}"))?
            {
                inv_recips.push(e);
            }
        }
        Ok(inv_recips)
    }
    /// Add a new tag by name.
    ///
    /// Errors: `TagExists`
    pub fn create_tag(&mut self, tag_name: &str) -> Result<()> {
        let mut added = false;
        self.pdb.tags.entry(tag_name.to_string()).or_insert_with(|| {
            added = true;
            pb::Strlist::default()
        });
        added.then_some(()).ok_or(TagExists(tag_name.to_string()))
    }
    /// Delete a tag by name.
    ///
    /// All records with the tag are implicitly detagged.
    ///
    /// Returns: The list of records that were detagged
    ///
    /// Errors: `NoSuchTag`
    pub fn delete_tag(&mut self, tag_name: &str) -> Result<Vec<String>> {
        self.pdb
            .tags
            .remove(tag_name)
            .map(|x| x.str)
            .ok_or(NoSuchTag(tag_name.to_string()))
    }
    /// Access the list of records with the given tag for modification.
    ///
    /// Errors: `NoSuchTag`
    fn get_mut_tag_rcds(&mut self, tag_name: &str) -> Result<&mut Vec<String>> {
        let tv = self
            .pdb
            .tags
            .get_mut(tag_name)
            .ok_or(NoSuchTag(tag_name.to_string()))?;
        Ok(&mut tv.str)
    }
    /// Access the list of records with the given tag.
    ///
    /// Errors: `NoSuchTag`
    pub fn get_tag_rcds(&self, tag_name: &str) -> Result<&Vec<String>> {
        let tv = self
            .pdb
            .tags
            .get(tag_name)
            .ok_or(NoSuchTag(tag_name.to_string()))?;
        Ok(&tv.str)
    }
    /// Tag a record.
    ///
    /// Errors: `NoSuchRecord`, `NoSuchTag`, `RecordHasTag`
    pub fn entag(&mut self, rcd_name: &str, tag_name: &str) -> Result<()> {
        self.get_mut_rcd(rcd_name)?;
        let tag_rcds = self.get_mut_tag_rcds(tag_name)?;
        (!tag_rcds.iter().any(|x| x == rcd_name))
            .then(|| tag_rcds.push(rcd_name.to_string()))
            .ok_or(RecordHasTag(rcd_name.to_string(), tag_name.to_string()))
    }
    /// Untag a record.
    ///
    /// Errors: `NoSuchRecord`, `NoSuchTag`, `RecordDoesNotHaveTag`
    pub fn detag(&mut self, rcd_name: &str, tag_name: &str) -> Result<()> {
        self.get_mut_rcd(rcd_name)?;
        let tag_rcds = self.get_mut_tag_rcds(tag_name)?;
        (vec_purge_eq(tag_rcds, &rcd_name.to_string()) > 0).then_some(()).ok_or(
            RecordDoesNotHaveTag(rcd_name.to_string(), tag_name.to_string()),
        )
    }
    /// Get all tags on the given record.
    ///
    /// Errors: `NoSuchRecord`
    pub fn tags_by_rcd(&self, rcd_name: &str) -> Result<Vec<String>> {
        self.get_rcd(rcd_name)?;
        let i = self.pdb.tags.iter();
        Ok(i.filter(|(_k, v)| v.str.iter().any(|x| x == rcd_name))
            .map(|(k, _v)| k.clone())
            .collect())
    }
}

//-----------------------------------------------------------------------------
// Wrapper objects that wrap various DB components. Currenty not used by db,
// just povided as convenience for use by other modules.
//-----------------------------------------------------------------------------

/// Basic `Vec<String>` formatter with Display
pub struct VecStringFmt<'a> {
    pub vec: &'a Vec<String>,
}
impl<'a> From<&'a Vec<String>> for VecStringFmt<'a> {
    fn from(x: &'a Vec<String>) -> VecStringFmt<'a> {
        VecStringFmt { vec: x }
    }
}
impl std::fmt::Display for VecStringFmt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut vec = self.vec.clone();
        vec.sort();
        write!(f, "{}", vec.join(", "))
    }
}

//-----------------------------------------------------------------------------
// Test
//-----------------------------------------------------------------------------
#[cfg(test)]
pub mod test_support {
    use super::*;

    /// Fake Crypto for testing
    pub struct Rot13;
    impl Crypto for Rot13 {
        fn encrypt(&mut self, data: &[u8]) -> AnyResult<Vec<u8>> {
            Ok(data.iter().map(|x| x.wrapping_add(13u8)).collect())
        }

        fn decrypt(&mut self, data: &[u8]) -> AnyResult<Vec<u8>> {
            Ok(data.iter().map(|x| x.wrapping_sub(13u8)).collect())
        }

        fn add_recipient(&mut self, _recipients: &str) -> AnyResult<()> {
            Ok(())
        }
    }
    pub struct IntoRot13;
    impl MkCrypto for IntoRot13 {
        fn mk_crypto(&self) -> AnyResult<impl Crypto> {
            Ok(Rot13)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn store_encrypt_decrypt() {
        let store = pb::Store::from([
            ("foo", "fooval"),
            ("bar", "barval"),
            ("baz", "bazval"),
        ]);
        let enc = store.encrypt(&mut Rot13).unwrap();
        assert_eq!(pb::Store::decrypt(&mut Rot13, &enc).unwrap(), store);
    }

    #[test]
    fn record_recipients_empty() {
        let rcd = pb::Record {
            recipient: Vec::<String>::default(),
            ..pb::Record::default()
        };
        assert_eq!(rcd.ref_recipients().count(), 0);
    }
    #[test]
    fn record_recipients() {
        let r_recips = vec!["r_one", "r_two", "r_three"];
        let rcd = pb::Record {
            recipient: r_recips.iter().map(|x| String::from(*x)).collect(),
            ..pb::Record::default()
        };
        assert_eq!(rcd.ref_recipients().collect::<Vec<_>>(), r_recips);
    }

    #[test]
    fn record_put_enc_get_dec_store() {
        // empty
        let empty = pb::Store::default();
        let mut rcd_empty = pb::Record::default();
        assert_eq!(rcd_empty.get_decrypt_store(&mut Rot13).unwrap(), empty);
        rcd_empty.put_encrypt_store(Rot13, &empty).unwrap();
        assert_eq!(rcd_empty, pb::Record::default());
        // populated
        let store = pb::Store::from([
            ("foo", "fooval"),
            ("bar", "barval"),
            ("baz", "bazval"),
        ]);
        let mut rcd = pb::Record::default();
        rcd.put_encrypt_store(Rot13, &store).unwrap();
        assert_eq!(rcd.get_decrypt_store(&mut Rot13).unwrap(), store);
    }

    #[test]
    fn record_enc_dec_inplace() {
        // empty
        let mut rcd_empty = pb::Record::default();
        rcd_empty.encrypt_inplace(Rot13).unwrap();
        assert_eq!(rcd_empty, pb::Record::default());
        rcd_empty.decrypt_inplace(&mut Rot13).unwrap();
        assert_eq!(rcd_empty, pb::Record::default());
        // populated
        let store = pb::Store::from([
            ("foo", "fooval"),
            ("bar", "barval"),
            ("baz", "bazval"),
        ]);
        let mut rcd = pb::Record::default();
        rcd.set_store(store.clone());
        rcd.payload = Some(pb::record::Payload::Store(store.clone()));
        rcd.encrypt_inplace(Rot13).unwrap();
        assert_eq!(rcd.get_decrypt_store(&mut Rot13).unwrap(), store);
        rcd.decrypt_inplace(&mut Rot13).unwrap();
        match &rcd.payload {
            Some(pb::record::Payload::Store(s)) => assert_eq!(s, &store),
            _ => panic!(),
        }
    }

    #[test]
    fn db_put_enc_get_dec_store() -> AnyResult<()> {
        let store = pb::Store::from([
            ("foo", "fooval"),
            ("bar", "barval"),
            ("baz", "bazval"),
        ]);
        let mut db = Db::default();
        db.new_rcd("foo")?;
        db.put_encrypt_rcd_store(Rot13, "foo", &store)?;
        assert_eq!(db.get_decrypt_rcd_store(&mut Rot13, "foo")?, store);
        Ok(())
    }
}
