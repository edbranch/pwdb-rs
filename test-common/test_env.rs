// Common test environment
use std::{env, fs, path::PathBuf, sync::Once};

pub const TEST_UID: &str = "tester@pwdb.local";
pub const TEST_KEY: &[u8] =
    include_bytes!("../test-common/tester@pwdb.local.key");
pub const TEST_DB_JSON: &str = include_str!("../test-common/test-db.json");

static INIT: Once = Once::new();

pub fn mk_gpg_context() -> gpgme::Result<gpgme::Context> {
    let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
    ctx.set_offline(true);
    ctx.set_engine_home_dir(gpg_homedir().to_str().unwrap())?;
    ctx.set_flag("trust-model", "always")?;
    Ok(ctx)
}

pub fn gpg_homedir() -> PathBuf {
    let mut d = env::current_dir().unwrap();
    d.push("gnupg");
    d
}

pub fn gpg_setup() {
    INIT.call_once(|| {
        gpgme::init().check_engine_version(gpgme::Protocol::OpenPgp).unwrap();
    });
    fs::create_dir(&gpg_homedir()).unwrap();
    let mut ctx = mk_gpg_context().unwrap();
    ctx.import(TEST_KEY).unwrap();
}

pub fn gpg_teardown() {
    // Gpgme tests call `gpgconf --kill all` but how does that work? Aren't
    // multiple gpg tests running at once? How does it know to only kill procs
    // associated with this test? What does it kill and why do they use it?
    //
    // `sealed_test` cleans up the test directory, so do we need to do
    // anything here?
}
