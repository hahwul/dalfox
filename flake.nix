{
  description = "Dalfox - A powerful open-source XSS scanner and utility focused on automation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    let
      # The single source of truth for the version is Cargo.toml. Reading it
      # here keeps `nix build` from drifting behind a release (this file used
      # to carry its own literal that had to be bumped in lockstep).
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      # Not `eachDefaultSystem`: nixpkgs 26.11 dropped x86_64-darwin, so
      # keeping it in the list makes `nix flake check --all-systems` (and any
      # evaluation of that attribute) fail outright.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      # The derivation, written callPackage-style so the same definition backs
      # both `packages.default` (built with the pinned rust-overlay toolchain)
      # and `overlays.default` (built with whatever rustPlatform the consumer's
      # nixpkgs provides).
      dalfoxPackage =
        {
          lib,
          stdenv,
          rustPlatform,
          installShellFiles,
          versionCheckHook,
        }:
        let
          # Cross-compiling to a platform the builder cannot execute rules out
          # everything that runs the result.
          canRunResult = stdenv.buildPlatform.canExecute stdenv.hostPlatform;
        in
        rustPlatform.buildRustPackage (finalAttrs: {
          pname = "dalfox";
          version = cargoToml.package.version;

          # Only the inputs cargo actually reads. Editing docs/, skills/ or a
          # workflow then no longer invalidates the build.
          #
          # `./tests` is here even though `doCheck = false` skips it: unit
          # tests under src/ reach for fixtures like tests/fixtures/sample.har
          # through CARGO_MANIFEST_DIR, so dropping it would make the package
          # un-testable the moment anyone flips doCheck on to debug something.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./build.rs
              ./src
              ./tests
            ];
          };

          cargoLock.lockFile = ./Cargo.lock;

          # dalfox is pure Rust: reqwest is pinned to rustls + ring
          # (`default-features = false`), so there is no openssl-sys or
          # aws-lc-sys in the graph and hence nothing for pkg-config to find.
          # `installShellFiles` provides `installShellCompletion` below.
          nativeBuildInputs = [ installShellFiles ];

          # Most of the suite drives live HTTP mock servers and (for the OOB
          # paths) outbound DNS, neither of which exists in the build sandbox.
          # CI runs `cargo test` for real; this build only has to produce a
          # working binary. Matches nixpkgs' own dalfox package.
          doCheck = false;

          # ... so gate the build on something the sandbox *can* prove: that
          # the binary starts and reports the version we claim to have built.
          # Both this and postInstall below run the freshly built binary, so
          # they share one predicate and must stay in lockstep: rendering the
          # man page without smoke-testing the binary (or vice versa) is not a
          # combination we want to be able to reach by editing one of them.
          nativeInstallCheckInputs = [ versionCheckHook ];
          doInstallCheck = canRunResult;
          versionCheckProgramArg = "--version";

          # Render the man page and the shell completions with the binary that
          # was just installed rather than shipping generated copies in the
          # source tree.
          postInstall = lib.optionalString canRunResult ''
            mkdir -p $out/share/man/man1
            $out/bin/dalfox man > $out/share/man/man1/dalfox.1
            installShellCompletion --cmd dalfox \
              --bash <($out/bin/dalfox completion bash) \
              --zsh <($out/bin/dalfox completion zsh) \
              --fish <($out/bin/dalfox completion fish)
          '';

          meta = {
            description = "Powerful open-source XSS scanner and utility focused on automation";
            homepage = "https://github.com/hahwul/dalfox";
            changelog = "https://github.com/hahwul/dalfox/releases/tag/v${finalAttrs.version}";
            license = lib.licenses.mit;
            maintainers = [ ];
            mainProgram = "dalfox";
            platforms = lib.platforms.unix;
          };
        });
    in
    flake-utils.lib.eachSystem systems (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        inherit (pkgs) lib;

        # Building only needs cargo + rustc + std, so use the `minimal`
        # profile: rustfmt, clippy and the docs would otherwise be dragged
        # into the build closure for nothing.
        #
        # `latest` is relative to the *locked* rust-overlay, so it silently
        # falls behind whenever Cargo.toml's `rust-version` moves first. The
        # assertion turns that into an actionable eval-time error (caught by
        # the cheap `nix flake check --no-build`) instead of an opaque rustc
        # failure a few hundred crates into the build.
        buildToolchain =
          assert lib.assertMsg
            (lib.versionAtLeast pkgs.rust-bin.stable.latest.minimal.version cargoToml.package.rust-version)
            ''
              flake.lock pins Rust ${pkgs.rust-bin.stable.latest.minimal.version}, but Cargo.toml
              requires rust-version ${cargoToml.package.rust-version}. Run `just nix-update`.
            '';
          pkgs.rust-bin.stable.latest.minimal;

        # The dev shell wants the full kit — `default` already carries rustfmt
        # and clippy (`just lint`), plus the sources rust-analyzer resolves
        # `std` against.
        devToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };

        # `buildRustPackage` takes its cargo/rustc from `rustPlatform`, not
        # from `nativeBuildInputs` — listing a toolchain there does not change
        # what actually compiles. Bind it explicitly so the pinned toolchain is
        # the one that builds dalfox.
        rustPlatform = pkgs.makeRustPlatform {
          cargo = buildToolchain;
          rustc = buildToolchain;
        };

        dalfox = pkgs.callPackage dalfoxPackage { inherit rustPlatform; };
      in
      {
        packages = {
          default = dalfox;
          inherit dalfox;
        };

        # A plain `nix flake check` builds this. Note that both CI and
        # `just nix-check` pass `--no-build` (evaluation only, all systems) and
        # get their build coverage from the separate `nix build` step, which
        # covers the CI runner's system alone.
        checks.default = dalfox;

        apps.default = flake-utils.lib.mkApp { drv = dalfox; } // {
          meta.description = "Run the Dalfox XSS scanner";
        };

        # `nixfmt-tree` rather than bare `nixfmt`: `nix fmt` hands the
        # formatter a directory, which nixfmt itself cannot take.
        formatter = pkgs.nixfmt-tree;

        devShells.default = pkgs.mkShell {
          packages = [
            devToolchain
            pkgs.just
            pkgs.cargo-watch
            pkgs.cargo-edit
            # The gates under scripts/ (`just harness`, `just version-check`,
            # `just docs-lint`, …) are Crystal programs.
            pkgs.crystal
          ];

          env.RUST_BACKTRACE = "1";

          shellHook = ''
            echo "🦊 Dalfox development environment ($(rustc --version))"
            echo "Run 'just' to see available commands"
            echo "Run 'cargo build' to build the project"
            echo "Run 'cargo test' to run tests"
          '';
        };
      }
    )
    // {
      # For NixOS / home-manager users who want dalfox built against their own
      # nixpkgs rather than this flake's pin:
      #   nixpkgs.overlays = [ dalfox.overlays.default ];
      overlays.default = final: prev: {
        dalfox = final.callPackage dalfoxPackage { };
      };
    };
}
