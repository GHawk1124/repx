{
  description = "repx - reproducible process attestations for supply chain security";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustNightly = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustNightly;

        # Source filtering.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (pkgs.lib.hasSuffix ".rs" path) ||
            (pkgs.lib.hasSuffix ".toml" path) ||
            (pkgs.lib.hasSuffix ".lock" path) ||
            (pkgs.lib.hasInfix "/repx-ebpf/.cargo/" path) ||
            (type == "directory");
        };

        # -----------------------------------------------------------------
        # bpf-linker: pre-built binary from GitHub releases.
        #
        # bpf-linker must use the same LLVM as rustc. The pre-built
        # releases use rust-llvm (Rust's bundled LLVM), which matches
        # our nightly toolchain. Building from source is impractical
        # in nix because aya-rustc-llvm-proxy's build script runs
        # `cargo metadata`, which is incompatible with nix vendoring.
        # -----------------------------------------------------------------
        bpf-linker-bin = let
          srcs = {
            "x86_64-linux" = pkgs.fetchurl {
              url = "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.2/bpf-linker-x86_64-unknown-linux-gnu.tar.gz";
              sha256 = "sha256-pLDucJCCVgCoKES5VfGXGyQSoBqF9ptMpX18NxGfJLo=";
            };
            "aarch64-linux" = pkgs.fetchurl {
              url = "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.2/bpf-linker-aarch64-unknown-linux-gnu.tar.gz";
              sha256 = pkgs.lib.fakeSha256;
            };
          };
        in pkgs.stdenv.mkDerivation {
          pname = "bpf-linker";
          version = "0.10.2";
          src = srcs.${system} or (throw "bpf-linker: unsupported system ${system}");
          sourceRoot = ".";
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          installPhase = ''
            mkdir -p $out/bin
            cp bpf-linker $out/bin/
          '';
        };

        # -----------------------------------------------------------------
        # eBPF bytecode
        #
        # We use the full repo source so that repx-ebpf can resolve its
        # path dependency on ../repx-common. Crate dependencies are
        # vendored via crane's vendorCargoDeps.
        # -----------------------------------------------------------------
        ebpfSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (pkgs.lib.hasSuffix ".rs" path) ||
            (pkgs.lib.hasSuffix ".toml" path) ||
            (pkgs.lib.hasSuffix ".lock" path) ||
            (pkgs.lib.hasInfix "/repx-ebpf/.cargo/" path) ||
            (type == "directory");
        };

        # Vendor crate deps for the eBPF build (offline builds in sandbox).
        ebpfVendored = craneLib.vendorCargoDeps {
          src = ebpfSrc;
          cargoLock = ./repx-ebpf/Cargo.lock;
        };

        # Also vendor the Rust sysroot deps needed by -Z build-std=core.
        rustSysroot = "${rustNightly}/lib/rustlib/src/rust";
        sysrootVendored = craneLib.vendorCargoDeps {
          src = rustSysroot;
          cargoLock = "${rustSysroot}/library/Cargo.lock";
        };

        repx-ebpf = pkgs.stdenv.mkDerivation {
          pname = "repx-ebpf";
          version = "0.1.0";
          src = ebpfSrc;

          nativeBuildInputs = [
            rustNightly
            bpf-linker-bin
          ];

          buildPhase = ''
            export HOME=$(mktemp -d)
            export CARGO_HOME=$HOME/.cargo

            # Build a merged vendor directory with both crate and sysroot deps.
            # crane vendoring puts crates inside a hash-named subdirectory.
            mkdir -p merged-vendor
            for d in ${ebpfVendored}/*/; do
              for crate in "$d"*/; do
                name=$(basename "$crate")
                [ -e "merged-vendor/$name" ] || ln -s "$crate" "merged-vendor/$name"
              done
            done
            for d in ${sysrootVendored}/*/; do
              for crate in "$d"*/; do
                name=$(basename "$crate")
                [ -e "merged-vendor/$name" ] || ln -s "$crate" "merged-vendor/$name"
              done
            done

            echo "Vendored crates: $(ls merged-vendor | wc -l)"

            # Write cargo config with vendored sources.
            mkdir -p repx-ebpf/.cargo
            cat > repx-ebpf/.cargo/config.toml <<TOML
            [source.crates-io]
            replace-with = "vendored-sources"

            [source.vendored-sources]
            directory = "$(pwd)/merged-vendor"

            [build]
            target = "bpfel-unknown-none"

            [unstable]
            build-std = ["core"]

            [target.bpfel-unknown-none]
            linker = "bpf-linker"
            TOML

            echo "Using bpf-linker: $(command -v bpf-linker)"
            echo "bpf-linker version: $(bpf-linker --version)"

            cd repx-ebpf
            cargo build --release \
              -Z build-std=core \
              --target bpfel-unknown-none
          '';

          installPhase = ''
            mkdir -p $out/lib
            cp repx-ebpf/target/bpfel-unknown-none/release/repx-ebpf $out/lib/repx-ebpf.o \
              || cp target/bpfel-unknown-none/release/repx-ebpf $out/lib/repx-ebpf.o
          '';
        };

        # Userspace binary with embedded eBPF bytecode.
        commonArgs = {
          inherit src;
          pname = "repx";
          version = "0.1.0";
          cargoExtraArgs = "--package repx";
          REPX_EBPF_BIN = "${repx-ebpf}/lib/repx-ebpf.o";
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        repx = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

        # Wrapper scripts for running integration tests with the nix-built repx.
        test-script = pkgs.writeShellApplication {
          name = "repx-test";
          runtimeInputs = [ repx pkgs.gcc ];
          text = builtins.readFile ./tests/run-test.sh;
        };

        test-nix-build-script = pkgs.writeShellApplication {
          name = "repx-test-nix-build";
          runtimeInputs = [ repx pkgs.gcc pkgs.coreutils ];
          text = builtins.readFile ./tests/run-nix-build-test.sh;
        };

        demo-attack-script = pkgs.writeShellApplication {
          name = "repx-demo-attack";
          runtimeInputs = [ repx pkgs.gcc pkgs.coreutils pkgs.gnugrep ];
          text = builtins.readFile ./tests/demo-attack.sh;
        };

        demo-nix-build-script = pkgs.writeShellApplication {
          name = "repx-demo-nix-build";
          runtimeInputs = [ repx pkgs.gcc pkgs.coreutils pkgs.gnugrep pkgs.gnused ];
          text = builtins.readFile ./tests/demo-nix-build.sh;
        };

        demo-real-nix-build-script = pkgs.writeShellApplication {
          name = "repx-demo-real-nix-build";
          runtimeInputs = [ repx pkgs.gcc pkgs.coreutils pkgs.gnugrep pkgs.gnused pkgs.nix ];
          text = builtins.readFile ./tests/demo-real-nix-build.sh;
        };

      in
      {
        packages = {
          inherit repx repx-ebpf bpf-linker-bin;
          default = repx;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = repx;
        };

        apps.test = flake-utils.lib.mkApp {
          drv = test-script;
        };

        apps.test-nix-build = flake-utils.lib.mkApp {
          drv = test-nix-build-script;
        };

        apps.demo-attack = flake-utils.lib.mkApp {
          drv = demo-attack-script;
        };

        apps.demo-nix-build = flake-utils.lib.mkApp {
          drv = demo-nix-build-script;
        };

        apps.demo-real-nix-build = flake-utils.lib.mkApp {
          drv = demo-real-nix-build-script;
        };

        devShells.default = craneLib.devShell {
          packages = [
            bpf-linker-bin
            pkgs.bpftools
            pkgs.elfutils
            pkgs.pkg-config
            pkgs.openssl
            pkgs.llvmPackages.libclang
            pkgs.llvmPackages.clang
            pkgs.linuxHeaders
            pkgs.zlib
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            echo "repx development environment loaded"
            echo "  Rust: $(rustc --version)"
            echo "  bpf-linker: $(bpf-linker --version 2>&1)"
            echo ""
            echo "Build commands:"
            echo "  ./build.sh                             # build eBPF + userspace"
            echo "  nix build                              # pure nix build"
            echo "  sudo ./result/bin/repx trace -o att.json -- <cmd>"
          '';
        };
      });
}
