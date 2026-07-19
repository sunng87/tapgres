{
  description = "Passively tap a local PostgreSQL port and decode its wire traffic to stdout";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix, flake-utils, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # --- package build (for `nix build`) ---
        craneLib = crane.mkLib pkgs;
        # Use the same stable Rust toolchain the dev shell uses, so edition 2024
        # is reliably supported.
        rustToolchain = fenix.packages.${system}.stable.withComponents [
          "cargo"
          "rustc"
        ];
        craneLib' = craneLib.overrideToolchain rustToolchain;

        # tapgres's only native dependency is libpcap. Its nixpkgs split
        # output puts the headers in `out` and the shared library in `lib`, so
        # we need both for compile-time and runtime. `pandoc` is needed at
        # build time to render the man page's Markdown sections to ROFF (see
        # examples/gen_manpage.rs).
        nativeBuildInputs = with pkgs; [ pkg-config pandoc ];
        buildInputs = with pkgs; [ libpcap libpcap.lib ];

        # Source cleaning: keep cargo's own selection (crane's
        # commonCargoSources — every .rs/.toml/Cargo.lock across the workspace),
        # plus committed non-Rust inputs used by builds and tests. Cargo does
        # not track these files, so commonCargoSources strips them unless the
        # fileset includes them explicitly.
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            (craneLib.fileset.commonCargoSources ./.)
            ./man/sections.md
            ./tests/fixtures/session-v1.jsonl
          ];
        };

        tapgres = craneLib'.buildPackage {
          inherit src;
          strictDeps = true;
          inherit nativeBuildInputs buildInputs;
          # The fenix toolchain links libpcap by name but doesn't auto-inject
          # its store path into the binary's RUNPATH the way the nixpkgs
          # cc-wrapper does. Bake it in explicitly so the binary runs without
          # LD_LIBRARY_PATH.
          RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.libpcap.lib}/lib";
          # The manpage is generated (never committed) from the clap CLI
          # definition plus Markdown prose in `man/sections.md`. Build the
          # gen_manpage example (which embeds the Markdown and shells out to
          # pandoc) and run it at install time, so `nix build` ships a page
          # that always matches the current options. nixpkgs'
          # compressManPages hook then gzip-compresses it to
          # `share/man/man1/tapgres.1.gz`.
          postInstall = ''
            cargo build --release --example gen_manpage
            install -d $out/share/man/man1
            ./target/release/examples/gen_manpage > $out/share/man/man1/tapgres.1
          '';
        };

      in
      {
        packages.default = tapgres;
        packages.tapgres = tapgres;

        checks.default = tapgres;

        # --- dev environment ---
        # Only what tapgres needs: the Rust toolchain, a C linker, and
        # libpcap. A local postgres is included so you have something to point
        # the tap at during development.
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.clang
            pkgs.git
            pkgs.mold
            (fenix.packages.${system}.stable.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
              "rust-analyzer"
            ])
            pkgs.postgresql_18.out
            pkgs.pandoc
          ];

          buildInputs = [
            pkgs.libpcap
            pkgs.libpcap.lib
          ];

          shellHook = ''
            export CC=clang
            export CXX=clang++
            # bake libpcap's location into the binary's RUNPATH so a `cargo run`
            # binary runs without the devshell's LD_LIBRARY_PATH
            export RUSTFLAGS="-C link-arg=-Wl,-rpath,${pkgs.libpcap.lib}/lib"
          '';
        };
      });
}
