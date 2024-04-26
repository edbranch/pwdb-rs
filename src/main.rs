// Copyright (C) 2024 Edward Branch
// SPDX-License-Identifier: GPL-3.0-only

//! Password Database application main.

mod cli_common;
pub mod db;
mod db_cli;
pub mod gpgh;
pub mod pb;
mod record_cli;
use db::Crypto;

use anyhow::{Context, Error, Result};
use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;
use file_lock::{FileLock, FileOptions};
use protobuf::Message;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs,
    path::{Path, PathBuf},
};

const DB_FILE_DEFAULT: &str = "pwdb.gpg";

struct AllocZeroOnDealloc;
unsafe impl GlobalAlloc for AllocZeroOnDealloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        std::ptr::write_bytes(
            ptr,
            0u8,
            layout.size() / std::mem::size_of::<u8>(),
        );
        System.dealloc(std::hint::black_box(ptr), layout)
    }
}
#[global_allocator]
static GLOBAL: AllocZeroOnDealloc = AllocZeroOnDealloc;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct ProgArgs {
    #[arg(short, long, value_name = "PWDB_FILE", global = true,
        help = "Password database file",
        value_hint = clap::ValueHint::FilePath)]
    file: Option<PathBuf>,
    #[arg(long, global = true,
        help = "gpgh home directory",
        value_hint = clap::ValueHint::DirPath)]
    gpg_homedir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<SubCommands>,
}

impl ProgArgs {
    fn cmd_dispatch(&self, maybe_mk_gpgh: Option<gpgh::MkGpgh>) -> Result<()> {
        let mk_gpgh = maybe_mk_gpgh
            .unwrap_or_else(|| gpgh::MkGpgh::new(self.gpg_homedir.clone()));
        match &self.command {
            None => cmd_open(&OpenArgs { file: self.file.clone() }, mk_gpgh),
            Some(SubCommands::Open(a)) => cmd_open(a, mk_gpgh),
            Some(SubCommands::Create(a)) => cmd_create(a, mk_gpgh),
            Some(SubCommands::Recrypt(a)) => cmd_recrypt(a, mk_gpgh),
            Some(SubCommands::Import(a)) => cmd_import(a, mk_gpgh),
            Some(SubCommands::Export(a)) => cmd_export(a, mk_gpgh),
        }
    }
}

#[derive(Debug, Subcommand)]
enum SubCommands {
    #[command(about = "[default] Open the database for interactive use")]
    Open(OpenArgs),
    #[command(about = "Create a new database")]
    Create(CreateArgs),
    #[command(about = "Re-encrypt all records and the database")]
    Recrypt(RecryptArgs),
    #[command(about = "Import database from JSON")]
    Import(ImportArgs),
    #[command(about = "Export database to JSON")]
    Export(ExportArgs),
}

#[derive(Debug, Args)]
struct OpenArgs {
    #[arg(from_global)]
    file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CreateArgs {
    #[arg(from_global)]
    file: Option<PathBuf>,
    #[arg(short, long, help = "UID of signer and encryption recipient")]
    uid: String,
}

#[derive(Debug, Args)]
struct RecryptArgs {
    #[arg(from_global)]
    file: Option<PathBuf>,
    #[arg(short, long, help = "UID of signer an encryption recipient")]
    uid: Option<String>,
}

#[derive(Debug, Args)]
struct ImportArgs {
    #[arg(from_global)]
    file: Option<PathBuf>,
    #[arg(short, long, help = "UID of signer an encryption recipient")]
    uid: Option<String>,
    #[arg(value_name = "JSON_FILE", help = "JSON file to import",
        value_hint = clap::ValueHint::FilePath)]
    infile: PathBuf,
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[arg(from_global)]
    file: Option<PathBuf>,
    #[arg(short, long, help = "UID of signer and encryption recipient")]
    uid: Option<String>,
    #[arg(value_name = "JSON_FILE", help = "Target JSON file for export",
        value_hint = clap::ValueHint::FilePath)]
    outfile: PathBuf,
}

fn cmd_open(cmd_args: &OpenArgs, mk_gpgh: gpgh::MkGpgh) -> Result<()> {
    let db_file = db_file_path(cmd_args.file.clone())?;
    println!("Opening {}", db_file.display());
    let (_flock, mut rdb) = db_open(
        &db_file,
        FileOptions::new().read(true).write(true),
        &mk_gpgh,
        None,
    )?;
    match db_cli::db_cli_run(&mut rdb, &mk_gpgh).context("db cli")? {
        cli_common::RetVal { modified: true, aborted: false } => {
            println!("Modified, encrypting and saving changes...");
            rdb.encrypt_all_rcds(&mk_gpgh)?
                .into_iter()
                .for_each(|e| eprintln!("Warning: {e:?}"));
            db_write_existing(&rdb, &db_file, mk_gpgh)?;
        }
        cli_common::RetVal { modified: true, aborted: true } => {
            println!("Discarding modifications and exiting")
        }
        cli_common::RetVal { modified: false, aborted: _ } => {
            println!("Not modified, exiting")
        }
    }
    Ok(())
}

fn cmd_create(cmd_args: &CreateArgs, mk_gpgh: gpgh::MkGpgh) -> Result<()> {
    let db_path = db_file_path_prepare_create(cmd_args.file.clone())?;
    let rdb = db::Db::new(pb::pwdb::DB {
        uid: cmd_args.uid.clone(),
        ..Default::default()
    });
    db_write_new(&rdb, &db_path, mk_gpgh)?;
    println!("Created {:?}", db_path.canonicalize()?);
    Ok(())
}

fn cmd_recrypt(cmd_args: &RecryptArgs, mk_gpgh: gpgh::MkGpgh) -> Result<()> {
    let db_file = db_file_path(cmd_args.file.clone())?;
    println!("Re-encrypting {}", db_file.display());
    let (_flock, mut rdb) = db_open(
        &db_file,
        FileOptions::new().read(true).write(true),
        &mk_gpgh,
        cmd_args.uid.clone(),
    )?;
    rdb.recrypt_all_rcds(&mk_gpgh)?
        .into_iter()
        .for_each(|e| eprintln!("Warning: {e:?}"));
    println!("Saving...");
    db_write_existing(&rdb, &db_file, mk_gpgh)
}

fn cmd_import(cmd_args: &ImportArgs, mk_gpgh: gpgh::MkGpgh) -> Result<()> {
    let db_path = db_file_path_prepare_create(cmd_args.file.clone())?;
    println!("Importing to {}", db_path.display());
    let infile = fs::File::open(&cmd_args.infile)
        .with_context(|| format!("openning {:?}", &cmd_args.infile))?;

    // Decrypt JSON with GPGME and parse to DB
    let mut decrypted = Vec::<u8>::new();
    let verify_str =
        mk_gpgh.mk_gpgh()?.decrypt_and_verify_data(infile, &mut decrypted)?;
    println!("{verify_str}");
    let mut rdb = db::Db::new(
        protobuf_json_mapping::parse_from_str::<pb::pwdb::DB>(
            std::str::from_utf8(&decrypted).context("from UTF8")?,
        )
        .context("parsing JSON")?,
    );
    if let Some(u) = &cmd_args.uid {
        *rdb.mut_uid() = u.to_string();
    }
    // Encrypt and write the DB
    rdb.encrypt_all_rcds(&mk_gpgh)?
        .into_iter()
        .for_each(|e| eprintln!("Warning: {e:?}"));
    db_write_new(&rdb, &db_path, mk_gpgh)?;
    Ok(())
}

fn cmd_export(cmd_args: &ExportArgs, mk_gpgh: gpgh::MkGpgh) -> Result<()> {
    let db_file = db_file_path(cmd_args.file.clone())?;
    println!("Exporting {}", db_file.display());
    let outfile = &cmd_args.outfile;
    let (_flock, mut rdb) = db_open(
        &db_file,
        FileOptions::new().read(true),
        &mk_gpgh,
        cmd_args.uid.clone(),
    )?;
    rdb.decrypt_all_rcds(&mk_gpgh)?;
    // Export to JSON
    let json = protobuf_json_mapping::print_to_string_with_options(
        rdb.get_pdb(),
        &protobuf_json_mapping::PrintOptions {
            proto_field_name: true,
            ..Default::default()
        },
    )?;
    let uid = rdb.get_pdb().uid.as_str();
    let mut gpgh = mk_gpgh
        .set_signer(uid.to_string())
        .mk_gpgh()
        .context("creating context for sign and encrypt")?;
    gpgh.add_recipient(uid)?;
    gpgh.sign_and_encrypt_data(
        json,
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(outfile)
            .with_context(|| format!("openning {:?}", outfile))?,
    )
    .context("sign and encrypt")?;
    Ok(())
}

fn db_open(
    db_path: &Path, fopts: FileOptions, mk_gpgh: &gpgh::MkGpgh,
    uid: Option<String>,
) -> Result<(FileLock, db::Db)> {
    let mut flock = open_with_lock(db_path, fopts)?;
    let mut decrypted = Vec::<u8>::new();
    let verify_str = mk_gpgh
        .mk_gpgh()?
        .decrypt_and_verify_data(&mut flock.file, &mut decrypted)?;
    println!("{verify_str}");
    let mut rdb = db::Db::new(
        pb::pwdb::DB::parse_from_bytes(&decrypted).context("parsing db")?,
    );
    if let Some(u) = uid {
        *rdb.mut_uid() = u;
    };
    Ok((flock, rdb))
}

fn db_write_new(
    rdb: &db::Db, db_path: &Path, mk_gpgh: gpgh::MkGpgh,
) -> Result<()> {
    let mut flock = open_with_lock(
        db_path,
        FileOptions::new().write(true).create_new(true),
    )
    .with_context(|| format!("creating/locking {:?}", db_path))?;
    db_write(rdb, &mut flock.file, mk_gpgh)?;
    Ok(())
}

fn db_write_existing(
    rdb: &db::Db, db_path: &Path, mk_gpgh: gpgh::MkGpgh,
) -> Result<()> {
    let mut tmp_path = db_path.to_path_buf();
    tmp_path.set_extension("tmp").then_some(()).ok_or_else(|| {
        anyhow::Error::msg(format!("path {:?} has no filename", db_path))
    })?;
    db_write(
        rdb,
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&tmp_path)
            .with_context(|| format!("openning {:?}", &tmp_path))?,
        mk_gpgh,
    )?;
    fs::rename(&tmp_path, db_path)
        .with_context(|| format!("moving {tmp_path:?} to {db_path:?}"))?;
    Ok(())
}

fn db_write<'a>(
    rdb: &db::Db, out: impl gpgme::IntoData<'a>, mk_gpgh: gpgh::MkGpgh,
) -> Result<()> {
    let ser = rdb.get_pdb().write_to_bytes().context("serializing db")?;
    let uid = rdb.get_pdb().uid.as_str();
    let mut gpgh = mk_gpgh
        .set_signer(uid.to_string())
        .mk_gpgh()
        .context("creating context for sign and encrypt")?;
    gpgh.add_recipient(uid)?;
    if let Some(invalid_recips) = gpgh
        .add_recipients_fold(rdb.get_all_recipients())
        .context("invalid record recipients")
        .err()
    {
        eprintln!("Warning: {invalid_recips:?}");
    }
    gpgh.sign_and_encrypt_data(ser, out).context("sign and encrypt")
}

fn db_file_path_prepare_create(
    opt_db_file: Option<PathBuf>,
) -> Result<PathBuf> {
    Ok(match opt_db_file {
        Some(p) => p.to_path_buf(),
        None => {
            fs::create_dir_all(data_dir_default()?)?;
            data_file_default()?
        }
    })
}

fn db_file_path(file: Option<PathBuf>) -> Result<PathBuf> {
    Ok(match file {
        Some(dbf) => dbf,
        None => data_file_default().context("determining db file path")?,
    })
}

fn data_file_default() -> Result<PathBuf> {
    let d = data_dir_default()?;
    Ok(d.join(DB_FILE_DEFAULT))
}

fn data_dir_default() -> Result<PathBuf> {
    Ok(PathBuf::from(
        ProjectDirs::from("org", "", "pwdb")
            .ok_or_else(|| Error::msg("could not determine data directory"))?
            .data_dir(),
    ))
}

fn open_with_lock(file: &Path, fopts: FileOptions) -> Result<FileLock> {
    FileLock::lock(file, false, fopts)
        .with_context(|| format!("opening with lock {file:?}"))
}

fn main() -> Result<()> {
    let prog_args = ProgArgs::parse();
    gpgme::init()
        .check_engine_version(gpgme::Protocol::OpenPgp)
        .context("initializing gpgme")?;
    prog_args.cmd_dispatch(None)?;
    Ok(())
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

    use sealed_test::prelude::*;

    const TEST_DB: &str = "test-db.gpg";

    #[test]
    fn clap_check_cli() {
        use clap::CommandFactory;
        ProgArgs::command().debug_assert()
    }

    #[test]
    fn data_default_location() -> Result<()> {
        let dir = data_dir_default()?;
        let file = data_file_default()?;
        assert_eq!(file.parent().unwrap(), dir);
        Ok(())
    }

    fn new_mk_gpgh() -> gpgh::MkGpgh {
        gpgh::MkGpgh::new(Some(gpg_homedir()))
            .set_signer(TEST_UID.to_string())
            .add_flag("no-auto-check-trustdb", "1")
            .add_flag("trust-model", "always")
    }

    fn new_test_db() -> db::Db {
        let mut rdb = db::Db::new(
            protobuf_json_mapping::parse_from_str::<pb::pwdb::DB>(TEST_DB_JSON)
                .unwrap(),
        );
        *rdb.mut_uid() = TEST_UID.to_string();
        rdb
    }

    fn create_test_db_file() {
        let mk_gpgh = new_mk_gpgh();
        let mut rdb = new_test_db();
        rdb.encrypt_all_rcds(&mk_gpgh).unwrap();
        db_write_new(&rdb, Path::new(TEST_DB), mk_gpgh).unwrap();
    }

    fn open_test_db_file(mk_gpgh: &gpgh::MkGpgh) -> (FileLock, db::Db) {
        db_open(
            Path::new(TEST_DB),
            FileOptions::new().read(true),
            mk_gpgh,
            None,
        )
        .unwrap()
    }

    fn setup() {
        gpg_setup();
        create_test_db_file();
    }

    fn cli_run_line(line: &str, mk_gpgh: &gpgh::MkGpgh) -> Result<()> {
        let args = shell_words::split(line).unwrap();
        ProgArgs::parse_from(args).cmd_dispatch(Some(mk_gpgh.clone()))
    }

    fn cli_run_subcmd(subcmd: &str, mk_gpgh: &gpgh::MkGpgh) -> Result<()> {
        let line = format!("pwdb -f {TEST_DB} {subcmd}");
        cli_run_line(&line, mk_gpgh)
    }

    #[sealed_test(before = setup(), after = gpg_teardown())]
    fn setup_open_and_verify() {
        let mk_gpgh = new_mk_gpgh();
        let (_lock, mut rdb) = open_test_db_file(&mk_gpgh);
        rdb.decrypt_all_rcds(&mk_gpgh).unwrap();
        assert_eq!(rdb, new_test_db());
    }

    #[sealed_test(before = setup(), after = gpg_teardown())]
    fn export_import_roundtrip() {
        let mk_gpgh = new_mk_gpgh();
        let json_file = "db.json.gpg";
        let db_export_file = "export-db.gpg";
        cli_run_subcmd(&format!("export {json_file}"), &mk_gpgh).unwrap();
        cli_run_line(
            &format!("pwdb -f {db_export_file} import {json_file}"),
            &mk_gpgh,
        )
        .unwrap();
        let (_lock, mut rdb) = db_open(
            Path::new(db_export_file),
            FileOptions::new().read(true),
            &mk_gpgh,
            None,
        )
        .unwrap();
        rdb.decrypt_all_rcds(&mk_gpgh).unwrap();
        assert_eq!(rdb, new_test_db());
        assert!(
            cli_run_subcmd(&format!("import {json_file}"), &mk_gpgh).is_err()
        );
    }

    #[sealed_test(before = setup(), after = gpg_teardown())]
    fn recrypt_basic() {
        let mk_gpgh = new_mk_gpgh();
        cli_run_subcmd("recrypt", &mk_gpgh).unwrap();
        let (_lock, mut rdb) = open_test_db_file(&mk_gpgh);
        rdb.decrypt_all_rcds(&mk_gpgh).unwrap();
        assert_eq!(rdb, new_test_db());
    }

    #[sealed_test(before = gpg_setup(), after = gpg_teardown())]
    fn create_exclusive() {
        let mk_gpgh = new_mk_gpgh();
        cli_run_subcmd(&format!("create --uid {TEST_UID}"), &mk_gpgh).unwrap();
        let (_lock, rdb) = open_test_db_file(&mk_gpgh);
        let mut rdb_cmp = db::Db::default();
        *rdb_cmp.mut_uid() = TEST_UID.to_string();
        assert_eq!(rdb, rdb_cmp);
        assert!(cli_run_subcmd(&format!("create --uid {TEST_UID}"), &mk_gpgh)
            .is_err());
    }
}
