// Copyright (C) 2024 Edward Branch
// SPDX-License-Identifier: GPL-3.0-only

//! Command line interface for a record.

use super::{
    cli_common::{Action, RetVal, columnize, repl_run},
    pb::pwdb as pb,
};

use clap::arg;
use rustyline::Result as ReadlineResult;
use wildmatch::WildMatch;

/// Run the record CLI REPL.
pub fn rcd_cli_run(
    store: &mut pb::Store, name: &str,
) -> ReadlineResult<RetVal> {
    rcd_print(store, None);
    let mut cli = rcd_cli_parser();
    repl_run(&format!("{name}> "), |line| handle_cmdline(line, &mut cli, store))
}

fn rcd_cli_parser() -> clap::Command {
    clap::Command::new("pwdb-record")
        .about("Password database")
        .multicall(true)
        .subcommands([
            clap::Command::new("print")
                .about("Print key/values")
                .arg(arg!(pattern: [PATTERN] "Filter by key matches pattern")),
            clap::Command::new("set").about("Set record key/value").args([
                arg!(key: <KEY> "Key to set"),
                arg!(value: [VALUE] "Key value(s)").num_args(..),
            ]),
            clap::Command::new("unset")
                .about("Unset record key")
                .args([arg!(key: <KEY> "Key to unset")]),
            clap::Command::new("echo")
                .about("Echo the STRING's to standard output")
                .arg(arg!(args: [STRINGS]).num_args(..)),
            clap::Command::new("exit")
                .about("Exit the record saving modifications"),
            clap::Command::new("abort")
                .about("Exit the record discarding modifications"),
        ])
}

fn handle_cmdline(
    cmdline: &str, cli: &mut clap::Command, store: &mut pb::Store,
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
        Ok(matches) => rcd_cmd_dispatch(store, &matches),
        Err(err) => {
            eprintln!("{err}");
            Action::new().add_history()
        }
    }
}

fn rcd_cmd_dispatch(
    store: &mut pb::Store, matches: &clap::ArgMatches,
) -> Action {
    let (subname, sub_m) =
        matches.subcommand().unwrap_or_else(|| unreachable!());
    match subname {
        "set" => rcd_set(store, sub_m),
        "unset" => rcd_unset(store, sub_m),
        "print" => rcd_print(
            store,
            sub_m.get_one::<String>("pattern").map(String::as_str),
        ),
        "echo" => rcd_echo(sub_m),
        "exit" => Action::new().exit(),
        "abort" => Action::new().abort(),
        _ => {
            eprintln!("{subname:?} not yet implemented");
            Action::new().add_history()
        }
    }
}

fn rcd_set(store: &mut pb::Store, matches: &clap::ArgMatches) -> Action {
    let key = matches.get_one::<String>("key").unwrap();
    let val = match matches.get_many::<String>("value") {
        Some(vals) => vals.map(|x| x.as_str()).collect::<Vec<_>>().join(" "),
        None => "".to_string(),
    };
    store.values.insert(key.clone(), val);
    Action::new().set_modified()
}

fn rcd_unset(store: &mut pb::Store, matches: &clap::ArgMatches) -> Action {
    let key = matches.get_one::<String>("key").unwrap();
    if store.values.remove(key).is_none() {
        eprintln!("No such key {key:?}");
        Action::new().add_history()
    } else {
        Action::new().set_modified().add_history()
    }
}

fn rcd_print(store: &pb::Store, pattern: Option<&str>) -> Action {
    let maybe_pat = pattern.map(WildMatch::new);
    let mut entries = store
        .values
        .iter()
        .filter_map(|(k, v)| {
            let maybe_entry = match &maybe_pat {
                Some(pat) => pat.matches(k).then_some((k, v)),
                None => Some((k, v)),
            };
            maybe_entry.map(|(kf, vf)| vec![kf.clone(), vf.clone()])
        })
        .collect::<Vec<_>>();
    entries.sort();
    columnize(&mut entries);
    for ln in entries {
        println!("  {}", ln.join("  "));
    }
    Action::new().add_history()
}

fn rcd_echo(matches: &clap::ArgMatches) -> Action {
    match matches.get_many::<String>("args") {
        Some(args) => {
            println!("  {}", args.cloned().collect::<Vec<_>>().join(" "));
        }
        _ => println!(),
    }
    Action::new().add_history()
}

//-----------------------------------------------------------------------------
// Test
//-----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::ffi::OsString;

    #[test]
    fn clap_check_cli() {
        rcd_cli_parser().debug_assert();
    }

    struct Runner {
        cli: clap::Command,
        store: pb::Store,
    }

    impl Default for Runner {
        fn default() -> Self {
            Self { cli: rcd_cli_parser(), store: pb::Store::default() }
        }
    }

    impl Runner {
        fn run_args<I, T>(&mut self, itr: I) -> Result<Action, String>
        where
            I: IntoIterator<Item = T>,
            T: Into<OsString> + Clone,
        {
            let ret = match self.cli.try_get_matches_from_mut(itr) {
                Ok(matches) => rcd_cmd_dispatch(&mut self.store, &matches),
                Err(err) => match err.kind() {
                    clap::error::ErrorKind::DisplayHelp => Action::new(),
                    clap::error::ErrorKind::DisplayVersion => Action::new(),
                    _ => Err(err.to_string())?,
                },
            };
            Ok(ret)
        }

        fn run_line(&mut self, line: &str) -> Result<Action, String> {
            let args = shell_words::split(line).map_err(|e| e.to_string())?;
            self.run_args(args)
        }

        fn map_str(&self) -> HashMap<&str, &str> {
            let i = self.store.values.iter();
            i.map(|(k, v)| (k.as_str(), v.as_str())).collect::<HashMap<_, _>>()
        }
    }

    #[test]
    fn test_harness() -> Result<(), String> {
        let mut rnr = Runner::default();
        rnr.run_args(["echo", "hello", "from", "run_args"])?;
        rnr.run_line("echo Hello from run_line!")?;
        assert!(rnr.run_line("echo unmatched \"quote").is_err());
        assert!(rnr.run_line("echo unmatched \"quote").is_err());
        // Excersise some basic stuff to make sure they don't crash/error
        println!("---- help ----");
        rnr.run_line("help")?;
        println!("---- help echo ----");
        rnr.run_line("help echo")?;
        Ok(())
    }

    #[test]
    fn rcd_set() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert_eq!(rnr.run_line("set empty")?, Action::new().set_modified());
        rnr.run_line("set single a_single_value")?;
        rnr.run_line("set quoted \"a single value with spaces\"")?;
        rnr.run_line("set multiple these values should be joined")?;
        rnr.run_line("set overwritten I will be overwritten!")?;
        assert_eq!(
            rnr.run_line("set overwritten I will be the final value!")?,
            Action::new().set_modified()
        );
        let exp = HashMap::<&str, &str>::from([
            ("empty", ""),
            ("single", "a_single_value"),
            ("quoted", "a single value with spaces"),
            ("multiple", "these values should be joined"),
            ("overwritten", "I will be the final value!"),
        ]);
        assert_eq!(rnr.map_str(), exp);
        Ok(())
    }

    #[test]
    fn rcd_unset() -> Result<(), String> {
        let mut rnr = Runner::default();
        assert_eq!(rnr.run_line("unset empty")?, Action::new().add_history());
        rnr.run_line("set foo")?;
        rnr.run_line("set removed")?;
        rnr.run_line("set double removed")?;
        assert_eq!(
            rnr.run_line("unset removed")?,
            Action::new().set_modified().add_history()
        );
        assert_eq!(
            rnr.run_line("unset double")?,
            Action::new().set_modified().add_history()
        );
        assert_eq!(rnr.run_line("unset double")?, Action::new().add_history());
        let exp = HashMap::<&str, &str>::from([("foo", "")]);
        assert_eq!(rnr.map_str(), exp);
        Ok(())
    }
}
