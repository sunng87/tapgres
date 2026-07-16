//! Renders the tapgres manual page (`tapgres.1`) as ROFF.
//!
//! The standard sections (NAME, SYNOPSIS, DESCRIPTION, OPTIONS) are rendered
//! from the clap [`Command`] returned by [`tapgres::cli::command`], so every
//! option is documented from a single source of truth. Per-option detail that
//! used to live in hand-written ENVIRONMENT/FILES sections now rides on the
//! relevant args' `long_help` (also clap) and is rendered by clap_mangen.
//!
//! The remaining prose — the display-filter language, examples, exit status,
//! and see-also — has no representation in clap, so it is authored as Markdown
//! in [`SECTIONS_MD`] (committed at `man/sections.md`, human-editable) and
//! converted to ROFF by **pandoc** at generation time. This keeps content out
//! of Rust: to update the docs you edit Markdown, not this file.
//!
//! The page is written to **stdout**, so any build channel can capture it:
//!
//! ```sh
//! cargo run --example gen_manpage > man/tapgres.1            # refresh locally
//! cargo run --example gen_manpage -- man/tapgres.1            # ...or via a path
//! ./target/release/examples/gen_manpage > "$pkgdir/.../tapgres.1"   # in packaging
//! ```
//!
//! Regeneration needs `pandoc` on PATH (provided by the Nix build/devShell,
//! and by the `pandoc` makedep in packaging). The generated file is not
//! committed; `man/tapgres.1` is git-ignored.

use std::io::Write as _;
use std::process::{Command, Stdio};

use clap_mangen::Man;

use tapgres::cli;

/// Markdown source for the sections clap cannot express, embedded at compile
/// time so the generator binary is self-contained (no `man/sections.md` needs
/// to exist beside it at run time).
const SECTIONS_MD: &str = include_str!("../man/sections.md");

fn main() -> std::io::Result<()> {
    let page = generate();
    match std::env::args().nth(1) {
        Some(path) => {
            let path = std::path::Path::new(&path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &page)?;
            eprintln!("wrote {}", path.display());
        }
        None => std::io::stdout().write_all(page.as_bytes())?,
    }
    Ok(())
}

/// Build the complete manual page as a string.
fn generate() -> String {
    let man = Man::new(cli::command()).manual("tapgres Manual");

    // Standard sections, in order, taken straight from the clap definition
    // (including each option's long_help). Writing to a `Vec<u8>` cannot fail,
    // so the `?`-bearing clap_mangen calls are safe to unwrap here.
    let mut out = Vec::<u8>::new();
    man.render_title(&mut out).unwrap();
    man.render_name_section(&mut out).unwrap();
    man.render_synopsis_section(&mut out).unwrap();
    man.render_description_section(&mut out).unwrap();
    man.render_options_section(&mut out).unwrap();

    // Prose sections authored in Markdown (`man/sections.md`), rendered to
    // ROFF by pandoc. Editing them needs no Rust.
    out.extend(render_markdown(SECTIONS_MD).into_bytes());

    String::from_utf8(out).expect("clap_mangen/pandoc output is valid UTF-8")
}

/// Convert a Markdown fragment to a ROFF fragment (section bodies only, no
/// `.TH` title) via pandoc, so it can be spliced in after the clap-rendered
/// sections. Requires `pandoc` on PATH.
fn render_markdown(markdown: &str) -> String {
    let mut child = match Command::new("pandoc")
        .args(["--from", "markdown", "--to", "man"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("gen_manpage: could not run `pandoc` ({error}).");
            eprintln!("gen_manpage: install pandoc to regenerate the manual page.");
            std::process::exit(1);
        }
    };

    // Feed the Markdown on stdin, then close it so pandoc sees EOF and writes
    // the ROFF to stdout.
    {
        let stdin = child.stdin.take();
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(markdown.as_bytes());
        }
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("gen_manpage: failed to read pandoc output: {error}");
            std::process::exit(1);
        }
    };
    if !output.status.success() {
        eprintln!("gen_manpage: pandoc exited with status {}", output.status);
        std::process::exit(1);
    }
    String::from_utf8(output.stdout).expect("pandoc man output is valid UTF-8")
}
