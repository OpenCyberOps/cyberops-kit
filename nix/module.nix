# NixOS module: `programs.cyberops-kit`.
#
# Installs the `cyberops` CLI system-wide. Deliberately nothing more: no service, no
# timer, no network listener. CyberOps Kit runs only when a user invokes it, and it
# never phones home.
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.cyberops-kit;
in
{
  options.programs.cyberops-kit = {
    enable = lib.mkEnableOption "CyberOps Kit, the reproducible security report card CLI";

    withAI = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Include the optional AI advisory providers (Anthropic and OpenAI SDKs).
        The local Ollama provider needs neither. AI output is advisory only and
        never influences the score.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default.override {
        inherit (cfg) withAI;
      };
      defaultText = lib.literalExpression "cyberops-kit.packages.\${system}.default";
      description = "The CyberOps Kit package to install.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
  };
}
