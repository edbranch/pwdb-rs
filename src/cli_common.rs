// Copyright (C) 2024 Edward Branch
// SPDX-License-Identifier: GPL-3.0-only

//! Common REPL and helpers for `db_cli` and `record_cli`.

use rustyline::{error::ReadlineError, Result as ReadlineResult};

use std::env;

/// Environemt variable to set REPL line edit mode (defaults to "vi").
const ENV_EDIT_MODE: &str = "PWDB_EDIT_MODE";
const EDIT_MODE_EMACS: &str = "emacs";

/// Flags returned by `repl_run` in Ok to help caller know exit state.
#[derive(Default)]
pub struct RetVal {
    /// Target was modified, changes should be saved.
    pub modified: bool,
    /// CLI was aborted, any changes should be discarded.
    pub aborted: bool,
}

/// Action flags returned by the REPL line handler callback.
///
/// These actions are executed or propagated by `repl_run`.
#[derive(PartialEq, Default, Debug)]
pub struct Action {
    /// Exit the REPL normally.
    pub f_exit: bool,
    /// Abort the REPL, returning with `RetVal::aborted` set `true`.
    pub f_abort: bool,
    /// Add the invoking line to command history.
    pub f_add_history: bool,
    /// Set the target state `modified` flag.
    pub f_set_modified: bool,
}

impl Action {
    /// Create new `Action` with all flags cleared.
    pub fn new() -> Action {
        Action::default()
    }
    /// Set f_exit `Action` flag.
    pub fn exit(self) -> Self {
        Self { f_exit: true, ..self }
    }
    /// Set f_abort `Action` flag.
    pub fn abort(self) -> Self {
        Self { f_abort: true, ..self }
    }
    /// Set f_add_history `Action` flag.
    pub fn add_history(self) -> Self {
        Self { f_add_history: true, ..self }
    }
    /// Set f_set_modified `Action` flag.
    pub fn set_modified(self) -> Self {
        Self { f_set_modified: true, ..self }
    }
}

// Set rustyline edit mode.
fn edit_mode() -> rustyline::EditMode {
    match env::var(ENV_EDIT_MODE) {
        Ok(m) if m.as_str() == EDIT_MODE_EMACS => rustyline::EditMode::Emacs,
        _ => rustyline::EditMode::Vi,
    }
}

/// Columnize input for pretty display.
pub fn columnize(in_split: &mut [Vec<String>]) {
    // Find number of columns and width of each column
    // TODO: Tests for columnize
    let n_cols = in_split.iter().map(|x| x.len()).max().unwrap_or(0);
    let mut widths = vec![0; n_cols];
    for (i, col_w) in widths.iter_mut().enumerate() {
        *col_w = in_split
            .iter()
            .filter_map(|x| Some(x.get(i)?.chars().count()))
            .max()
            .unwrap_or(0);
    }
    // Expand all lines to n_cols, and all strings to column width
    for line in in_split.iter_mut() {
        line.resize(n_cols, String::new());
        for (col, v) in line.iter_mut().enumerate() {
            *v = format!("{0:w$}", v, w = widths[col]);
        }
    }
}

/// A simple REPL based on the rustyline input line editor.
pub fn repl_run(
    prompt: &str, mut handle_line: impl FnMut(&str) -> Action,
) -> ReadlineResult<RetVal> {
    let rl_cfg = rustyline::Config::builder()
        .max_history_size(1000)?
        .edit_mode(edit_mode())
        .build();
    let mut rl = rustyline::DefaultEditor::with_config(rl_cfg)?;
    let mut ret = RetVal::default();
    loop {
        match rl.readline(prompt) {
            Ok(line) => {
                let action = handle_line(&line);
                if action.f_set_modified {
                    ret.modified = true;
                }
                if action.f_add_history {
                    if let Err(e) = rl.add_history_entry(&line) {
                        eprintln!("{e}"); // Keep going, it's just history
                    }
                }
                if action.f_abort {
                    ret.aborted = true;
                    break;
                }
                if action.f_exit {
                    break;
                }
            }
            Err(ReadlineError::Eof) => break,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::WindowResized) => continue,
            Err(e) => Err(e)?,
        }
    }
    Ok(ret)
}
