{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.pkg-config pkgs.openssl pkgs.cargo-llvm-cov pkgs.chromium ];

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH = "${pkgs.chromium}/bin/chromium";
  scripts.check.exec = "exec ./scripts/check.sh";
  enterTest = "check";
}
