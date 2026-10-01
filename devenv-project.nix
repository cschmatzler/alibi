{ lib, pkgs, ... }:
{
  packages = [ pkgs.bun pkgs.pkg-config pkgs.openssl pkgs.cargo-llvm-cov pkgs.chromium ];
  env.LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.openssl ];
  env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH = "${pkgs.chromium}/bin/chromium";
  env.NO_PROXY = "localhost,127.0.0.1";
  env.no_proxy = "localhost,127.0.0.1";
  scripts.full-check.exec = "check && exec ./scripts/check.sh";
  enterTest = lib.mkForce "full-check";
}
