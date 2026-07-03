{
  description = "Monitor a local PostgreSQL port and decode its wire traffic to stdout";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
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

        # pgwiretap's only native dependency is libpcap. Its nixpkgs split
        # output puts the headers in `out` and the shared library in `lib`, so
        # we need both for compile-time and runtime.
        nativeBuildInputs = with pkgs; [ pkg-config ];
        buildInputs = with pkgs; [ libpcap libpcap.lib ];

        pgwiretap = craneLib'.buildPackage {
          src = craneLib'.cleanCargoSource ./.;
          strictDeps = true;
          inherit nativeBuildInputs buildInputs;
          # The fenix toolchain links libpcap by name but doesn't auto-inject
          # its store path into the binary's RUNPATH the way the nixpkgs
          # cc-wrapper does. Bake it in explicitly so the binary runs without
          # LD_LIBRARY_PATH.
          RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.libpcap.lib}/lib";
        };

      in
      {
        packages.default = pgwiretap;
        packages.pgwiretap = pgwiretap;

        checks.default = pgwiretap;

        # --- dev environment ---
        # Only what pgwiretap needs: the Rust toolchain, a C linker, and
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
