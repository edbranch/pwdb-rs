// Copyright (C) 2024 Edward Branch
// SPDX-License-Identifier: GPL-3.0-only

//! Command line interface for the password database

use super::{
    cli_common::{columnize, repl_run, Action, RetVal},
    db,
    pb::pwdb as pb,
    record_cli,
};

use anyhow::Context;
use clap::arg;
use crossterm::{
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use rustyline::Result as ReadlineResult;
use wildmatch::WildMatch;

use std::collections::HashMap;

/// Run the Db CLI REPL.
pub fn db_cli_run<C: db::MkCrypto>(
    rdb: &mut db::Db, mk_crypto: &C,
) -> ReadlineResult<RetVal> {
    let mut cli = db_cli_parser();
    repl_run("pwdb> ", |line| handle_cmdline(line, &mut cli, rdb, mk_crypto))
}

struct TermAltScreenGuard;
impl TermAltScreenGuard {
    fn new() -> db::Result<Self> {
        std::io::stdout()
            .execute(EnterAlternateScreen)
            .context("entering alternate screen")?;
        Ok(TermAltScreenGuard)
    }
}
impl Drop for TermAltScreenGuard {
    fn drop(&mut self) {
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
    }
}

fn db_cli_parser() -> clap::Command {
    clap::Command::new("pwdb")
        .about("Password database")
        .multicall(true)
        .subcommands([
        clap::Command::new("mk-record").about("Make a new record").args([
            arg!(comment: -c --comment <COMMENT> "Comment the new record"),
            arg!(tag: -t --tag <TAG> "Tag the record, multiples ok")
                .action(clap::ArgAction::Append),
            arg!(record: <RECORD> "Record to create"),
        ]),
        clap::Command::new("rm-record")
            .about("Remove a record")
            .args([arg!(record: <RECORD> "Record to remove")]),
        clap::Command::new("mod-record").about("Modify a record").args([
            arg!(comment: -c --comment <COMMENT> "Comment the record"),
            arg!(tag: -t --tag <TAG> "Tag the record, multiples ok")
                .action(clap::ArgAction::Append),
            arg!(untag: -u --untag <TAG> "Untag the record, multiples ok")
                .action(clap::ArgAction::Append),
            arg!(rename: -m --move <NEW_NAME> "Move/rename the record"),
            arg!(record: <RECORD> "Record to modify"),
        ]),
        clap::Command::new("cp-record").about("Copy a record").args([
            arg!(with_tags: -t "Tag DEST with all SOURCE tags")
                .long("with-tags"),
            arg!(src_rcd: <SOURCE> "Source record to copy"),
            arg!(dest_rcd: <DEST> "Destination record to copy to"),
        ]),
        clap::Command::new("open-record")
            .about("Open a record")
            .args([
                arg!(create: -c --create "Create record if it doesn't exist"),
                arg!(record: <RECORD> "Record to open"),
            ])
            .visible_alias("open"),
        clap::Command::new("ls-records")
            .about("List records")
            .args([
                arg!(verbose: -v --verbose "Increase verbosity"),
                arg!(tag: -t --tag <TAG> "Filter by tag, multiples ok")
                    .action(clap::ArgAction::Append),
                arg!(pattern: [PATTERN] "Filter by pattern match"),
            ])
            .visible_alias("ls"),
        clap::Command::new("mk-tag")
            .about("Make a new tag")
            .args([arg!(tag: <TAG> "New tag")]),
        clap::Command::new("rm-tag").about("Remove a tag").args([
            arg!(force: -f --force "Force removal even if not empty"),
            arg!(tag: <TAG> "Tag to remove"),
        ]),
        clap::Command::new("ls-tags").about("List tags").args([
            arg!(verbose: -v --verbose "Increase verbosity"),
            arg!(pattern: [PATTERN] "Filter by pattern match"),
        ]),
        clap::Command::new("echo")
            .about("Echo the STRING's to standard output")
            .arg(arg!(args: [STRINGS]).num_args(..)),
        clap::Command::new("exit")
            .about("Exit the program saving modifications"),
        clap::Command::new("abort")
            .about("Exit the program discarding modifications"),
    ])
}

fn handle_cmdline<C: db::MkCrypto>(
    cmdline: &str, cli: &mut clap::Command, rdb: &mut db::Db, mk_crypto: &C,
) -> Action {
    let args = match shell_words::split(cmdline) {
        Ok(v) if v.is_empty() => return Action::new(),
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return Action::new().add_history();
        }
    };
    match cli.try_get_matches_from_mut(args) {
        Ok(matches) => match db_cmd_dispatch(rdb, &matches, mk_crypto) {
            Ok(a) => return a,
            Err(e) => eprintln!("{e}"),
        },
        Err(e) => eprintln!("{e}"),
    }
    Action::new().add_history()
}

fn db_cmd_dispatch<C: db::MkCrypto>(
    rdb: &mut db::Db, matches: &clap::ArgMatches, mk_crypto: &C,
) -> db::Result<Action> {
    let (subname, sub_m) =
        matches.subcommand().unwrap_or_else(|| unreachable!());
    match subname {
        "mk-record" => dbc_mk_record(rdb, sub_m),
        "rm-record" => dbc_rm_record(rdb, sub_m),
        "mod-record" => dbc_mod_record(rdb, sub_m),
        "cp-record" => dbc_cp_record(rdb, sub_m),
        "open-record" => dbc_open_record(rdb, sub_m, mk_crypto),
        "ls-records" => dbc_ls_records(rdb, sub_m),
        "mk-tag" => dbc_mk_tag(rdb, sub_m),
        "rm-tag" => dbc_rm_tag(rdb, sub_m),
        "ls-tags" => dbc_ls_tags(rdb, sub_m),
        "echo" => dbc_echo(sub_m),
        "exit" => Ok(Action::new().exit()),
        "abort" => Ok(Action::new().abort()),
        _ => {
            eprintln!("{subname:?} not yet implemented");
            Ok(Action::new().add_history())
        }
    }
}

fn dbc_mk_record(
    rdb: &mut db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    if let Some(tags) = matches.get_many::<String>("tag") {
        all_tags_exist(rdb, tags)?;
    }
    let rcd_name = matches.get_one::<String>("record").unwrap();
    rdb.new_rcd(rcd_name)?;
    let tags = matches.get_many::<String>("tag");
    let untags = None::<std::slice::Iter<String>>;
    let comment = matches.get_one::<String>("comment").map(|x| x.as_str());
    mod_record_common(rdb, rcd_name, tags, untags, None, comment)?;
    Ok(Action::new().add_history().set_modified())
}

fn dbc_rm_record(
    rdb: &mut db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    let rcd_name = matches.get_one::<String>("record").unwrap();
    rdb.remove_rcd(rcd_name)?;
    Ok(Action::new().add_history().set_modified())
}

fn dbc_mod_record(
    rdb: &mut db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    // get all the args
    let rcd_name = matches.get_one::<String>("record").unwrap();
    let new_name = matches.get_one::<String>("rename").map(String::as_str);
    let tags = matches.get_many::<String>("tag");
    let untags = matches.get_many::<String>("untag");
    let comment = matches.get_one::<String>("comment").map(|x| x.as_str());
    // pre-validate args to prevent partial completion
    if let Some(n) = new_name {
        if rdb.get_rcd(n).is_ok() {
            return Err(db::Error::RecordExists(n.to_string()));
        }
    }
    if let Some(t) = tags.clone() {
        all_tags_exist(rdb, t)?;
    }
    if let Some(u) = untags.clone() {
        all_tags_exist(rdb, u)?;
    }
    // do the things
    mod_record_common(rdb, rcd_name, tags, untags, new_name, comment)
}

fn mod_record_common<'a, I, J>(
    rdb: &'a mut db::Db, rcd_name: &'a str, tags: Option<I>, untags: Option<J>,
    new_name: Option<&'a str>, comment: Option<&'a str>,
) -> db::Result<Action>
where
    I: Iterator<Item = &'a String>,
    J: Iterator<Item = &'a String>,
{
    let rcd = rdb.get_mut_rcd(rcd_name)?;
    let mut action = Action::new().add_history();
    if let Some(cmt) = comment {
        rcd.comment = cmt.to_string();
        action = action.set_modified();
    }
    if let Some(u) = untags {
        for tag in u {
            match rdb.detag(rcd_name, tag) {
                Ok(_) => {
                    action = action.set_modified();
                }
                Err(e) => {
                    eprintln!("{e} - continuing anyway");
                }
            }
        }
    }
    if let Some(t) = tags {
        for tag in t {
            match rdb.entag(rcd_name, tag) {
                Ok(_) => {
                    action = action.set_modified();
                }
                Err(e) => {
                    eprintln!("{e} - continuing anyway");
                }
            }
        }
    }
    if let Some(n) = new_name {
        rdb.new_rcd(n)?;
        for t in rdb.tags_by_rcd(rcd_name)?.iter() {
            rdb.entag(n, t)?;
        }
        *rdb.get_mut_rcd(n)? = rdb.remove_rcd(rcd_name)?;
        action = action.set_modified();
    }
    Ok(action)
}

fn dbc_cp_record(
    rdb: &mut db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    let src = matches.get_one::<String>("src_rcd").unwrap();
    let dest = matches.get_one::<String>("dest_rcd").unwrap();
    let src_rcd = rdb.get_rcd(src)?.clone();
    rdb.new_rcd(dest)?;
    if matches.get_flag("with_tags") {
        for t in rdb.tags_by_rcd(src)?.iter() {
            rdb.entag(dest, t)?;
        }
    }
    *rdb.get_mut_rcd(dest)? = src_rcd;
    Ok(Action::new().add_history().set_modified())
}

fn dbc_open_record<C: db::MkCrypto>(
    rdb: &mut db::Db, matches: &clap::ArgMatches, mk_crypto: &C,
) -> db::Result<Action> {
    let rcd_name = matches.get_one::<String>("record").unwrap();
    if matches.get_flag("create") {
        rdb.new_rcd(rcd_name)?;
    }
    let mut crypto = mk_crypto.mk_crypto()?;
    let mut store = rdb.get_decrypt_rcd_store(&mut crypto, rcd_name)?;
    let record_cli_res;
    {
        let _guard = TermAltScreenGuard::new()?;
        record_cli_res = record_cli::rcd_cli_run(&mut store, rcd_name);
    }
    match record_cli_res {
        Ok(RetVal { modified: true, aborted: false }) => {
            println!("Modified, encrypting {rcd_name}");
            rdb.put_encrypt_rcd_store(crypto, rcd_name, &store)?
                .inspect(|e| eprintln!("Warning: {e:?}"));
            Ok(Action::new().add_history().set_modified())
        }
        Ok(RetVal { modified: true, aborted: true }) => {
            println!("Discarding modifications and closing {rcd_name}");
            Ok(Action::new().add_history())
        }
        Ok(RetVal { modified: false, aborted: _ }) => {
            println!("Not modified, closing {rcd_name}");
            Ok(Action::new().add_history())
        }
        Err(e) => {
            eprintln!("Record CLI Error: {e}");
            Ok(Action::new().add_history())
        }
    }
}

fn dbc_ls_records(
    rdb: &db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    let tags = matches.get_many::<String>("tag");
    let pattern = matches.get_one::<String>("pattern");
    let verbose = matches.get_flag("verbose");
    let collected = ls_records_collect(rdb, tags, pattern.map(|s| s.as_str()))?;
    ls_records_print(rdb, collected, verbose);
    Ok(Action::new().add_history())
}

fn ls_records_collect<'a, 'b, I>(
    rdb: &'a db::Db, tags: Option<I>, pattern: Option<&'b str>,
) -> db::Result<Vec<(&'a String, &'a pb::Record)>>
where
    I: Iterator<Item = &'b String>,
{
    let rcds = match tags {
        Some(tag_itr) => {
            let ri = tag_itr
                .map(|x| rdb.get_tag_rcds(x))
                .collect::<db::Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .filter_map(|rn| {
                    rdb.get_rcd(rn).map_or(None, |r| Some((rn, r)))
                });
            records_filter_pattern(ri, pattern).collect::<Vec<_>>()
        }
        None => {
            let ri = rdb.get_pdb().records.iter();
            records_filter_pattern(ri, pattern).collect::<Vec<_>>()
        }
    };
    Ok(rcds)
}

fn records_filter_pattern<'a, I>(
    rcds: I, pattern: Option<&str>,
) -> impl Iterator<Item = (&'a String, &'a pb::Record)>
where
    I: Iterator<Item = (&'a String, &'a pb::Record)>,
{
    let mpat = pattern.map(WildMatch::new);
    rcds.filter_map(move |(k, v)| match &mpat {
        Some(pat) => pat.matches(k).then_some((k, v)),
        None => Some((k, v)),
    })
}

// Support struct for printing records in verbose via Display
#[derive(Default, Debug)]
struct RecordPrn {
    name: String,
    comment: String,
    tags: Vec<String>,
}

impl std::fmt::Display for RecordPrn {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let indent = "    ";
        writeln!(f, "{}: {}", self.name, self.comment)?;
        write!(f, "{indent}tags: {}", db::VecStringFmt::from(&self.tags))
    }
}

fn ls_records_print<'a>(
    rdb: &'a db::Db, mut rcds: Vec<(&'a String, &'a pb::Record)>, verbose: bool,
) {
    rcds.sort_by_key(|(k, _v)| *k);
    if verbose {
        rcds.into_iter()
            .map(|(n, r)| RecordPrn {
                name: n.clone(),
                comment: r.comment.clone(),
                tags: rdb.tags_by_rcd(n.as_str()).unwrap(),
            })
            .for_each(|x| println!("  {x}"));
    } else {
        let sep = "    ";
        let mut split_lines = rcds
            .into_iter()
            .map(|(n, r)| vec![n.clone(), r.comment.clone()])
            .collect::<Vec<Vec<String>>>();
        columnize(&mut split_lines);
        split_lines
            .into_iter()
            .map(|x| x.join(sep))
            .for_each(|x| println!("  {x}"));
    }
}

fn dbc_mk_tag(
    rdb: &mut db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    let tag_name = matches.get_one::<String>("tag").unwrap();
    rdb.create_tag(tag_name)?;
    Ok(Action::new().add_history().set_modified())
}

fn dbc_rm_tag(
    rdb: &mut db::Db, matches: &clap::ArgMatches,
) -> db::Result<Action> {
    let tag_name = matches.get_one::<String>("tag").unwrap();
    if !matches.get_flag("force") && !(rdb.get_tag_rcds(tag_name)?).is_empty() {
        eprintln!("Tag {tag_name:?} not empty. Use --force to override.");
        return Ok(Action::new().add_history());
    }
    let detagged = rdb.delete_tag(tag_name)?;
    if !detagged.is_empty() {
        eprintln!("Detagged records: {detagged:?}");
    }
    Ok(Action::new().add_history().set_modified())
}

fn dbc_ls_tags(rdb: &db::Db, matches: &clap::ArgMatches) -> db::Result<Action> {
    let pattern = matches.get_one::<String>("pattern");
    let collected = ls_tags_collect(rdb, pattern.map(|x| x.as_str()));
    ls_tags_print(collected, matches.get_flag("verbose"));
    Ok(Action::new().add_history())
}

fn ls_tags_collect<'a>(
    rdb: &'a db::Db, pattern: Option<&str>,
) -> HashMap<&'a String, &'a pb::Strlist> {
    let mpat = pattern.map(WildMatch::new);

    let tags = &rdb.get_pdb().tags;
    tags.iter()
        .filter(|(k, _v)| match &mpat {
            Some(pat) => pat.matches(k),
            None => true,
        })
        .collect::<HashMap<&String, &pb::Strlist>>()
}

fn ls_tags_print(tags: HashMap<&String, &pb::Strlist>, verbose: bool) {
    if verbose {
        let mut tc = tags
            .into_iter()
            .map(|(k, v)| {
                let mut rcds = v.str.clone();
                rcds.sort();
                vec![k.clone() + ":", rcds.join(", ")]
            })
            .collect::<Vec<_>>();
        tc.sort();
        columnize(&mut tc);
        for ln in tc {
            println!("  {}", ln.join("  "));
        }
    } else {
        let mut keys = tags.into_keys().cloned().collect::<Vec<String>>();
        keys.sort();
        println!("  {}", keys.join(", "));
    }
}

fn dbc_echo(matches: &clap::ArgMatches) -> db::Result<Action> {
    match matches.get_many::<String>("args") {
        Some(args) => {
            println!("  {}", args.cloned().collect::<Vec<_>>().join(" "));
        }
        _ => println!(),
    }
    Ok(Action::new().add_history())
}

fn all_tags_exist<'a, I>(rdb: &db::Db, tag_iter: I) -> db::Result<()>
where
    I: Iterator<Item = &'a String>,
{
    for tag_name in tag_iter {
        rdb.get_tag_rcds(tag_name)?;
    }
    Ok(())
}

//-----------------------------------------------------------------------------
// Test
//-----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::db::test_support::*;
    use super::*;
    use std::collections::HashSet;
    use std::ffi::OsString;

    #[test]
    fn clap_check_cli() {
        db_cli_parser().debug_assert();
    }

    struct Runner {
        cli: clap::Command,
        rdb: db::Db,
    }

    impl Default for Runner {
        fn default() -> Self {
            Self { cli: db_cli_parser(), rdb: db::Db::default() }
        }
    }

    impl Runner {
        fn run_args<I, T>(&mut self, itr: I) -> Result<Action, String>
        where
            I: IntoIterator<Item = T>,
            T: Into<OsString> + Clone,
        {
            Ok(match self.cli.try_get_matches_from_mut(itr) {
                Ok(matches) => {
                    db_cmd_dispatch(&mut self.rdb, &matches, &IntoRot13)
                        .map_err(|e| e.to_string())?
                }
                Err(err) => match err.kind() {
                    clap::error::ErrorKind::DisplayHelp => Action::new(),
                    clap::error::ErrorKind::DisplayVersion => Action::new(),
                    _ => Err(err.to_string())?,
                },
            })
        }

        fn run_line(&mut self, line: &str) -> Result<Action, String> {
            let args = shell_words::split(line).map_err(|e| e.to_string())?;
            self.run_args(args)
        }
    }

    #[test]
    fn test_harness() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_args(["echo", "hello", "from", "run_args"])?;
        rnr.run_line("echo Hello from run_line!")?;
        assert!(rnr.run_line("echo unmatched \"quote").is_err());
        // Excersise some basic stuff to make sure they don't crash/error
        println!("---- help ----");
        rnr.run_line("help")?;
        println!("---- help echo ----");
        rnr.run_line("help echo")?;
        println!("---- ls-records ----");
        rnr.run_line("ls-records")?;
        rnr.run_line("ls-records -v")?;
        println!("---- ls-tags ----");
        rnr.run_line("ls-tags")?;
        rnr.run_line("ls-tags -v")?;
        Ok(())
    }

    #[test]
    fn mk_record_basic_no_tags() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert!(rnr.rdb.get_rcd("non-existent").is_err());
        assert_eq!(
            rnr.run_line("mk-record no_comment")?,
            Action::new().add_history().set_modified()
        );
        rnr.rdb.get_rcd("no_comment").map_err(|e| e.to_string())?;
        rnr.run_line("mk-record chatterbox -c \"lots to say\"")?;
        assert_eq!(
            rnr.rdb.get_rcd("chatterbox").unwrap().comment,
            "lots to say"
        );
        assert!(rnr.run_line("mk-record chatterbox").is_err());
        assert_eq!(
            rnr.rdb.get_rcd("chatterbox").unwrap().comment,
            "lots to say"
        );
        Ok(())
    }

    #[test]
    fn rm_record_basic_no_tags() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert!(rnr.run_line("rm-record non-existent").is_err());
        rnr.run_line("mk-record first")?;
        rnr.run_line("mk-record second")?;
        assert_eq!(
            rnr.run_line("rm-record first")?,
            Action::new().add_history().set_modified()
        );
        assert!(rnr.run_line("rm-record first").is_err());
        rnr.run_line("rm-record second")?;
        assert!(rnr.run_line("rm-record second").is_err());
        Ok(())
    }

    #[test]
    fn mod_record_basic_no_tags() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert!(rnr.run_line("mod-record non-existent").is_err());
        rnr.run_line("mk-record first")?;
        assert_eq!(
            rnr.run_line("mod-record first -c\"The first record\"")?,
            Action::new().add_history().set_modified()
        );
        assert_eq!(
            rnr.rdb.get_rcd("first").unwrap().comment,
            "The first record"
        );
        rnr.run_line("mod-record first -c\"The first record modified\"")?;
        assert_eq!(
            rnr.rdb.get_rcd("first").unwrap().comment,
            "The first record modified"
        );
        rnr.run_line("mk-record movable -c\"Will be moved\"")?;
        assert!(rnr.run_line("mod-record movable -m first").is_err());
        assert_eq!(
            rnr.run_line("mod-record movable -m moved")?,
            Action::new().add_history().set_modified()
        );
        assert!(rnr.rdb.get_rcd("movable").is_err());
        assert_eq!(rnr.rdb.get_rcd("moved").unwrap().comment, "Will be moved");
        Ok(())
    }

    #[test]
    fn copy_record() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag a-tag")?;
        rnr.run_line("mk-record src -t a-tag -c cmt")?;
        rnr.run_line("mk-record exists")?;
        assert!(rnr.run_line("cp-record src exists").is_err());
        assert_eq!(
            rnr.run_line("cp-record src no-tags")?,
            Action::new().add_history().set_modified()
        );
        assert!(rnr.rdb.tags_by_rcd("no-tags").unwrap().is_empty());
        assert_eq!(
            rnr.rdb.get_rcd("no-tags").unwrap(),
            rnr.rdb.get_rcd("src").unwrap()
        );
        assert_eq!(
            rnr.run_line("cp-record --with-tags src with-tags")?,
            Action::new().add_history().set_modified()
        );
        assert_eq!(
            HashSet::from_iter(
                rnr.rdb.tags_by_rcd("with-tags").unwrap().into_iter()
            ),
            HashSet::from(["a-tag".to_string()])
        );
        Ok(())
    }

    #[test]
    fn mk_tag_basic_no_tagged_records() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert_eq!(
            rnr.run_line("mk-tag first")?,
            Action::new().add_history().set_modified()
        );
        rnr.run_line("mk-tag second")?;
        assert!(rnr.run_line("mk-tag first").is_err());
        assert!(rnr.rdb.get_pdb().tags.contains_key("first"));
        assert!(rnr.rdb.get_pdb().tags.contains_key("second"));
        Ok(())
    }

    #[test]
    fn rm_tag_basic_no_tagged_records() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert!(rnr.run_line("rm-tag non-existent").is_err());
        rnr.run_line("mk-tag first")?;
        rnr.run_line("mk-tag second")?;
        assert_eq!(
            rnr.run_line("rm-tag first")?,
            Action::new().add_history().set_modified()
        );
        rnr.run_line("rm-tag -f second")?;
        assert!(!rnr.rdb.get_pdb().tags.contains_key("first"));
        assert!(!rnr.rdb.get_pdb().tags.contains_key("second"));
        Ok(())
    }

    // ls_tags_collect(...) wrapper to adapt inputs from literals and output
    // to a HashMap of (tag, HashSet(records)) so it can be compared to
    // a literal without regard to order.
    fn lstc<'a, 'b>(
        rnr: &'a Runner, pattern: Option<&'b str>,
    ) -> HashMap<&'a str, HashSet<&'a str>> {
        ls_tags_collect(&rnr.rdb, pattern)
            .into_iter()
            .map(|(t, sl)| {
                (
                    t.as_str(),
                    sl.str
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<HashSet<&str>>(),
                )
            })
            .collect::<HashMap<&str, HashSet<&str>>>()
    }

    #[test]
    fn mod_record_with_tags() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-record foo")?;
        rnr.run_line("mk-record bar")?;
        rnr.run_line("mk-record foobar")?;
        assert!(rnr.run_line("mod-record foo -t foosies").is_err());
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-tag barsies")?;
        assert_eq!(
            rnr.run_line("mod-record foo -t foosies")?,
            Action::new().add_history().set_modified()
        );
        rnr.run_line("mod-record bar -t barsies")?;
        rnr.run_line("mod-record foobar -t foosies -t barsies")?;
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo", "foobar"])),
                ("barsies", HashSet::from(["bar", "foobar"])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        rnr.run_line("mod-record foobar -u foosies -u barsies")?;
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo"])),
                ("barsies", HashSet::from(["bar"])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        // re-tag (not an error)
        assert_eq!(
            rnr.run_line("mod-record foo -t foosies")?,
            Action::new().add_history()
        );
        // re-untag (not an error)
        assert_eq!(
            rnr.run_line("mod-record foobar -u foosies")?,
            Action::new().add_history()
        );
        rnr.run_line("mk-record moveable")?;
        rnr.run_line("mod-record moveable -t foosies")?;
        rnr.run_line("mod-record moveable -m moved -t barsies")?;
        assert_eq!(
            HashSet::from_iter(
                rnr.rdb.tags_by_rcd("moved").unwrap().into_iter()
            ),
            HashSet::from(["foosies".to_string(), "barsies".to_string()])
        );
        Ok(())
    }

    #[test]
    fn mod_record_side_effects() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-tag barsies")?;
        rnr.run_line("mk-tag maybies")?;
        rnr.run_line("mk-record foo -t foosies")?;
        assert!(rnr
            .run_line("mod-record foo -t maybies -t none -c comment")
            .is_err());
        assert!(rnr.rdb.get_rcd("foo").unwrap().comment.is_empty());
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo"])),
                ("barsies", HashSet::from([])),
                ("maybies", HashSet::from([])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        rnr.run_line("mod-record foo -t maybies -c comment")?;
        assert!(rnr
            .run_line("mod-record foo -u maybies -u none -c \"\"")
            .is_err());
        assert_eq!(rnr.rdb.get_rcd("foo").unwrap().comment, "comment");
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo"])),
                ("barsies", HashSet::from([])),
                ("maybies", HashSet::from(["foo"])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        assert_eq!(
            rnr.run_line("mod-record foo -u barsies -u maybies")?,
            Action::new().add_history().set_modified()
        );
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo"])),
                ("barsies", HashSet::from([])),
                ("maybies", HashSet::from([])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        assert_eq!(
            rnr.run_line("mod-record foo -t foosies -t maybies")?,
            Action::new().add_history().set_modified()
        );
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo"])),
                ("barsies", HashSet::from([])),
                ("maybies", HashSet::from(["foo"])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        rnr.run_line("mk-record movable -t maybies")?;
        {
            let exp = rnr.rdb.get_pdb().clone();
            assert!(rnr
                .run_line("mod-record movable -m moved -t none -c cmt")
                .is_err());
            assert!(rnr
                .run_line("mod-record movable -m foo -t barsies -c cmt")
                .is_err());
            assert_eq!(rnr.rdb.get_pdb(), &exp);
        }
        Ok(())
    }

    #[test]
    fn mk_record_with_tags() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-tag barsies")?;
        rnr.run_line("mk-tag zoosies")?;
        rnr.run_line("mk-record foobar -t foosies -t barsies")?;
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foobar"])),
                ("barsies", HashSet::from(["foobar"])),
                ("zoosies", HashSet::from([])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        Ok(())
    }

    #[test]
    fn mk_record_side_effects() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag exists")?;
        assert!(rnr.run_line("mk-record squatter -t exists -t none").is_err());
        assert!(rnr.rdb.get_rcd("squatter").is_err());
        {
            let exp = HashMap::from([("exists", HashSet::from([]))]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        assert_eq!(
            rnr.run_line("mk-record tagger -t exists -t exists -c comment")?,
            Action::new().add_history().set_modified()
        );
        assert_eq!(rnr.rdb.get_rcd("tagger").unwrap().comment, "comment");
        {
            let exp = HashMap::from([("exists", HashSet::from(["tagger"]))]);
            assert_eq!(lstc(&rnr, Some("exists")), exp);
        }
        Ok(())
    }

    #[test]
    fn rm_record_with_tags() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-tag barsies")?;
        rnr.run_line("mk-record foo -t foosies")?;
        rnr.run_line("mk-record foobar -t foosies -t barsies")?;
        rnr.run_line("rm-record foo")?;
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foobar"])),
                ("barsies", HashSet::from(["foobar"])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        Ok(())
    }

    #[test]
    fn rm_tag_with_tagged_records() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-record foo -t foosies")?;
        // NOTE: rm-tag prints and fails, but doesn't actually Err()
        // It's OK because we test that it didn't remove the tag after.
        assert_eq!(
            rnr.run_line("rm-tag foosies")?,
            Action::new().add_history()
        );
        {
            let exp = HashMap::from([("foosies", HashSet::from(["foo"]))]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        assert_eq!(
            rnr.run_line("rm-tag -f foosies")?,
            Action::new().add_history().set_modified()
        );
        assert!(lstc(&rnr, None).is_empty());
        Ok(())
    }

    #[test]
    fn ls_tags_collect_basic() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-tag barsies")?;
        rnr.run_line("mk-tag empty")?;
        rnr.run_line("mk-record foo -t foosies")?;
        rnr.run_line("mk-record bar -t barsies")?;
        rnr.run_line("mk-record foobar -t foosies -t barsies")?;
        rnr.run_line("mk-record zoo")?;
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo", "foobar"])),
                ("barsies", HashSet::from(["bar", "foobar"])),
                ("empty", HashSet::from([])),
            ]);
            assert_eq!(lstc(&rnr, None), exp);
        }
        {
            let exp = HashMap::from([
                ("foosies", HashSet::from(["foo", "foobar"])),
                ("barsies", HashSet::from(["bar", "foobar"])),
            ]);
            assert_eq!(lstc(&rnr, Some("*sies")), exp);
        }
        {
            let exp =
                HashMap::from([("barsies", HashSet::from(["bar", "foobar"]))]);
            assert_eq!(lstc(&rnr, Some("bar*")), exp);
        }
        Ok(())
    }

    // ls_records_collect(...) wrapper to adapt inputs from literals and output
    // to a HashMap of (name, comment) so it can be compared without regard to
    // order.
    fn lsrc<'a, 'b>(
        rnr: &'a Runner, tags: Option<&'b [&'b str]>, pattern: Option<&'b str>,
    ) -> HashMap<&'a str, &'a str> {
        let tagsv = tags.map(|tags_slice| {
            tags_slice
                .iter()
                .map(|tag_str| tag_str.to_string())
                .collect::<Vec<String>>()
        });
        let tagsvi = tagsv.as_ref().map(|v| v.iter());
        ls_records_collect(&rnr.rdb, tagsvi, pattern)
            .unwrap()
            .into_iter()
            .map(|(tag, rcd)| (tag.as_str(), rcd.comment.as_str()))
            .collect::<HashMap<_, _>>()
    }

    #[test]
    fn ls_records_collect_basic() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_line("mk-tag foosies")?;
        rnr.run_line("mk-tag barsies")?;
        rnr.run_line("mk-tag empty")?;
        rnr.run_line("mk-record foo -c \"I'm foo!\" -t foosies")?;
        rnr.run_line("mk-record bar -c \"Bar here!\" -t barsies")?;
        rnr.run_line("mk-record foobar -t foosies -t barsies")?;
        rnr.run_line("mk-record zoo -c \"Zoozoo!\"")?;
        {
            let rcds = lsrc(&rnr, None, None);
            let exp = HashMap::from([
                ("zoo", "Zoozoo!"),
                ("foo", "I'm foo!"),
                ("bar", "Bar here!"),
                ("foobar", ""),
            ]);
            assert_eq!(rcds, exp);
        }
        {
            let rcds = lsrc(&rnr, Some(&["foosies"]), None);
            let exp = HashMap::from([("foo", "I'm foo!"), ("foobar", "")]);
            assert_eq!(rcds, exp);
        }
        {
            let rcds = lsrc(&rnr, Some(&["foosies", "barsies"]), None);
            let exp = HashMap::from([
                ("foo", "I'm foo!"),
                ("bar", "Bar here!"),
                ("foobar", ""),
            ]);
            assert_eq!(rcds, exp);
        }
        {
            let rcds = lsrc(&rnr, Some(&["foosies", "barsies"]), Some("???"));
            let exp =
                HashMap::from([("foo", "I'm foo!"), ("bar", "Bar here!")]);
            assert_eq!(rcds, exp);
        }
        {
            let rcds = lsrc(&rnr, None, Some("*oo*"));
            let exp = HashMap::from([
                ("foo", "I'm foo!"),
                ("foobar", ""),
                ("zoo", "Zoozoo!"),
            ]);
            assert_eq!(rcds, exp);
        }
        Ok(())
    }
}
