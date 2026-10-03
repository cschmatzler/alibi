{
  inputs,
  lib,
  pkgs,
  ...
}:
{
  imports = [ inputs.rust-style.devenvModules.default ];

  packages = [
    pkgs.bun
    pkgs.sops
    pkgs.pkg-config
    pkgs.openssl
    pkgs.cargo-llvm-cov
    pkgs.lcov
    pkgs.chromium
  ];
  env.LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.openssl ];
  env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH = "${pkgs.chromium}/bin/chromium";
  env.NO_PROXY = "localhost,127.0.0.1";
}
