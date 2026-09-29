{
  description = "CyberOps Kit — reproducible, auditable security report cards for any software project";

  # One input. Systems are enumerated by hand rather than through flake-utils: every
  # input is supply chain surface, and we would fail our own audit if we were
  # careless about it.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        # Orchestrator plus every scanner, pinned by flake.lock.
        cyberops-kit = pkgs.callPackage ./nix/package.nix { };
        # Orchestrator only; uses whatever scanners are already on PATH.
        cyberops-kit-minimal = cyberops-kit.override { withScanners = false; };
        # Everything, plus the optional AI advisory providers.
        cyberops-kit-ai = cyberops-kit.override { withAI = true; };
        default = cyberops-kit;
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          meta.description = "Run CyberOps Kit";
        };
      });

      overlays.default = final: _prev: {
        cyberops-kit = final.callPackage ./nix/package.nix { };
      };

      nixosModules.default = import ./nix/module.nix self;

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          # The Python toolchain comes from nixpkgs, not pip: pip's manylinux wheels
          # (pydantic-core, ruff, mypy) cannot load on NixOS without an FHS loader.
          # Every `make` target works as-is; `make install` is not needed here.
          packages = [
            (pkgs.python3.withPackages (
              ps: with ps; [
                # runtime, including the `ai` extra
                typer
                pydantic
                structlog
                jinja2
                pyyaml
                anthropic
                openai
                # dev
                pytest
                pytest-asyncio
                pytest-cov
                mypy
                ruff
                types-pyyaml
              ]
            ))
            pkgs.pre-commit
            pkgs.gnumake
            pkgs.git
          ]
          # Scanners on PATH for `make selfscan` and `make test-integration`.
          ++ self.packages.${pkgs.stdenv.hostPlatform.system}.default.passthru.scanners;
          shellHook = ''
            export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            echo "CyberOps Kit dev shell: 'make test', 'make lint', 'make typecheck', 'make selfscan'."
          '';
        };
      });

      checks = forAllSystems (
        pkgs:
        let
          system = pkgs.stdenv.hostPlatform.system;
        in
        {
          inherit (self.packages.${system}) cyberops-kit cyberops-kit-minimal;
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Evaluate the NixOS module against a minimal system so a broken option
          # fails `nix flake check`, not a user's `nixos-rebuild`.
          nixos-module =
            let
              nixos = lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.default
                  {
                    programs.cyberops-kit.enable = true;
                    boot.loader.grub.enable = false;
                    fileSystems."/" = {
                      device = "/dev/null";
                      fsType = "ext4";
                    };
                    system.stateVersion = "26.05";
                  }
                ];
              };
            in
            pkgs.runCommand "cyberops-kit-nixos-module-check" { } ''
              test -x ${nixos.config.system.path}/bin/cyberops
              touch $out
            '';
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
