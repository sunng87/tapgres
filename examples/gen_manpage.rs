//! Renders the tapgres manual page (`tapgres.1`) as ROFF.
//!
//! The standard sections (NAME, SYNOPSIS, DESCRIPTION, OPTIONS) are rendered
//! from the clap [`Command`] returned by [`tapgres::cli::command`], so every
//! option is documented from a single source of truth. The display-filter
//! language is a separate mini-DSL with no representation in clap, so its
//! "DISPLAY FILTER EXPRESSIONS" section is hand-written with the `roff` crate
//! (which handles ROFF escaping) and inserted before the trailing VERSION
//! section.
//!
//! The page is written to **stdout**, so any build channel can capture it:
//!
//! ```sh
//! cargo run --example gen_manpage > man/tapgres.1            # refresh locally
//! cargo run --example gen_manpage -- man/tapgres.1            # ...or via a path
//! ./target/release/examples/gen_manpage > "$pkgdir/.../tapgres.1"   # in packaging
//! ```
//!
//! The generated file is not committed; `man/tapgres.1` is git-ignored.

use std::io::Write as _;

use clap_mangen::Man;
use roff::{Roff, bold, roman};

use tapgres::cli;

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

    // Standard sections, in order, taken straight from the clap definition.
    let mut out = Vec::<u8>::new();
    // Writing to a `Vec<u8>` cannot fail, so the `?`-bearing clap_mangen calls
    // are safe to unwrap here.
    man.render_title(&mut out).unwrap();
    man.render_name_section(&mut out).unwrap();
    man.render_synopsis_section(&mut out).unwrap();
    man.render_description_section(&mut out).unwrap();
    man.render_options_section(&mut out).unwrap();

    // Hand-written sections that describe behaviour clap cannot infer.
    out.extend(display_filter_section().render().bytes());
    out.extend(examples_section().render().bytes());
    out.extend(environment_section().render().bytes());
    out.extend(files_section().render().bytes());
    out.extend(exit_status_section().render().bytes());

    // Trailing version + a SEE ALSO pointer.
    man.render_version_section(&mut out).unwrap();
    out.extend(see_also_section().render().bytes());

    String::from_utf8(out).expect("clap_mangen/roff output is valid UTF-8")
}

/// Adds a `field -- type. example` row as a `.TP` definition-list entry.
fn field_row(roff: &mut Roff, field: &str, type_: &str, example: &str, note: &str) {
    roff.control("TP", []);
    roff.text([bold(field), roman(format!("  {type_}."))]);
    let mut line = vec![roman("Example: "), bold(example.to_string())];
    if !note.is_empty() {
        line.push(roman(format!(" {note}")));
    }
    roff.text(line);
}

fn display_filter_section() -> Roff {
    let mut roff = Roff::default();
    roff.control("SH", ["DISPLAY FILTER EXPRESSIONS"]);
    roff.text([
        roman("The "),
        bold("-Y"),
        roman(" / "),
        bold("--display-filter"),
        roman(" option limits decoded PostgreSQL messages in line-oriented output and supplies the initial display filter in "),
        bold("--tui"),
        roman(" mode. The "),
        bold("-Y"),
        roman(" shorthand mirrors Wireshark's display filters. Its value is parsed once at startup; a parse error is fatal for stdout mode and is reported in the TUI footer (the last valid filter stays active)."),
    ]);

    roff.text([roman(
        "The expression language is a small, typed subset of Wireshark display-filter syntax: \
         named fields are compared with operators and combined with boolean connectives. \
         Capture errors and connection lifecycle notices are operational context, not decoded \
         protocol messages, so they are never filtered out.",
    )]);

    // Fields ---------------------------------------------------------------
    roff.control("SS", ["Fields"]);
    field_row(
        &mut roff,
        "client.ip",
        "IP address",
        "client.ip == 127.0.0.1",
        "",
    );
    field_row(
        &mut roff,
        "client.port",
        "integer",
        "client.port in {40005, 40006}",
        "",
    );
    field_row(
        &mut roff,
        "message.type",
        "string",
        "message.type == \"Query\"",
        "A decoded pgwire message type, e.g. Query, Parse, Bind, DataRow, RowDescription, ReadyForQuery.",
    );
    field_row(
        &mut roff,
        "message.text",
        "string",
        "message.text contains \"orders\"",
        "The text payload: the SQL statement for Query, the cached column value for a single-column DataRow, etc.",
    );
    field_row(
        &mut roff,
        "message.direction",
        "\"f2b\" or \"b2f\"",
        "message.direction == \"b2f\"",
        "f2b is client (frontend) to server (backend); b2f is the reverse.",
    );

    // Operators ------------------------------------------------------------
    roff.control("SS", ["Operators"]);
    roff.control("TP", []);
    roff.text([bold("=="), roman(", "), bold("!="), roman(
        " -- equality and inequality. Valid for every field. String and direction comparisons are case-sensitive.",
    )]);
    roff.control("TP", []);
    roff.text([bold("in {value, ...}"), roman(
        " -- set membership. Values must match the field's type; a quoted-string set for string/direction fields, a bare-integer or IP set for numeric/address fields.",
    )]);
    roff.control("TP", []);
    roff.text([bold("contains"), roman(
        " -- case-sensitive substring test. Valid only for the string fields message.type and message.text.",
    )]);
    roff.control("TP", []);
    roff.text([bold("matches"), roman(
        " -- case-insensitive, unanchored regular-expression match. Valid only for the string fields. Use a raw string such as r\"orders\\s+WHERE\" so backslashes reach the regex engine unescaped.",
    )]);

    // Combining predicates -------------------------------------------------
    roff.control("SS", ["Combining predicates"]);
    roff.text([
        roman("Combine predicates with "),
        bold("and"),
        roman(" / "),
        bold("&&"),
        roman(", "),
        bold("or"),
        roman(" / "),
        bold("||"),
        roman(", and "),
        bold("not"),
        roman(" / "),
        bold("!"),
        roman(", grouped with parentheses. Precedence, highest to lowest: "),
        bold("not"),
        roman(", then "),
        bold("and"),
        roman(", then "),
        bold("or"),
        roman(". String values must be double-quoted; backslash escapes (\\n, \\r, \\t, \\\", \\\\) are honoured in ordinary strings."),
    ]);

    // TUI interaction ------------------------------------------------------
    roff.control("SS", ["In the TUI"]);
    roff.text([
        roman("Press "),
        bold("y"),
        roman(" to edit the display filter. A valid edit is applied immediately to the full retained message buffer, so previously hidden messages reappear when the filter changes. An empty filter (or "),
        bold("Esc"),
        roman(") clears it. The message-view border is green normally, yellow while a filter is active, and red while the input is invalid."),
    ]);

    roff
}

fn examples_section() -> Roff {
    let mut roff = Roff::default();
    roff.control("SH", ["EXAMPLES"]);

    roff.control("TP", []);
    roff.text([roman("Monitor port 5432 on loopback (the defaults):")]);
    code(&mut roff, "tapgres");

    roff.control("TP", []);
    roff.text([roman("Capture on a specific interface:")]);
    code(&mut roff, "tapgres -p 5432 -i eth0");

    roff.control("TP", []);
    roff.text([roman(
        "Run the local TLS-terminating proxy against an upstream server:",
    )]);
    code(
        &mut roff,
        "tapgres --mode mitm --listen 127.0.0.1:15432 --upstream 127.0.0.1:5432",
    );

    roff.control("TP", []);
    roff.text([roman("Interactive view with an initial display filter:")]);
    code(
        &mut roff,
        "tapgres --tui -Y 'message.type in {\"Query\", \"DataRow\"} and message.text contains \"orders\"'",
    );

    roff.control("TP", []);
    roff.text([roman("Show only server-to-client errors and notices:")]);
    code(
        &mut roff,
        "tapgres -Y 'message.direction == \"b2f\" and message.type matches \"^Error|Notice$\"'",
    );

    roff.control("TP", []);
    roff.text([roman(
        "Grant capture privileges without running as root (pcap mode):",
    )]);
    code(&mut roff, "sudo setcap cap_net_raw+ep $(which tapgres)");

    roff
}

fn environment_section() -> Roff {
    let mut roff = Roff::default();
    roff.control("SH", ["ENVIRONMENT"]);

    roff.control("TP", []);
    roff.text([bold("XDG_CONFIG_HOME"), roman(", "), bold("HOME")]);
    roff.text([roman(
        "In mitm mode the auto-generated CA and server certificate are written under $XDG_CONFIG_HOME/tapgres, falling back to ~/.config/tapgres. Override the location with --tls-dir.",
    )]);

    roff
}

fn files_section() -> Roff {
    let mut roff = Roff::default();
    roff.control("SH", ["FILES"]);

    roff.control("TP", []);
    roff.text([
        bold("~/.config/tapgres/ca.crt"),
        roman(", "),
        bold("ca.key"),
    ]);
    roff.text([roman("The auto-generated CA used to sign the mitm-mode server certificate. Distribute ca.crt to clients that must trust the proxy.")]);

    roff.control("TP", []);
    roff.text([
        bold("~/.config/tapgres/server.crt"),
        roman(", "),
        bold("server.key"),
    ]);
    roff.text([roman(
        "The auto-generated leaf certificate, valid for localhost, 127.0.0.1 and ::1. Override with --tls-cert and --tls-key.",
    )]);

    roff
}

fn exit_status_section() -> Roff {
    let mut roff = Roff::default();
    roff.control("SH", ["EXIT STATUS"]);
    roff.text([roman(
        "tapgres exits 0 on a clean shutdown. A fatal capture/proxy error or an invalid --display-filter expression is reported on stderr and exits non-zero.",
    )]);
    roff
}

fn see_also_section() -> Roff {
    let mut roff = Roff::default();
    roff.control("SH", ["SEE ALSO"]);
    roff.text([roman(
        "psql(1), pg_dump(1). Project home and full documentation: https://github.com/sunng87/tapgres",
    )]);
    roff
}

/// A verbatim (no-fill) block, so SQL and shell snippets render exactly.
fn code(roff: &mut Roff, snippet: &str) {
    roff.control("nf", []);
    roff.text([roman(snippet)]);
    roff.control("fi", []);
}
