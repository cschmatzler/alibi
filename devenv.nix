{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.pkg-config pkgs.openssl pkgs.cargo-llvm-cov pkgs.chromium ];

  languages.rust = {
    enable = true;
    channel = "stable";
    version = "1.98.1";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "llvm-tools-preview" ];
  };

  env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH = "${pkgs.chromium}/bin/chromium";
  scripts.check.exec = "exec ./scripts/check.sh";
  enterTest = "check";
}
