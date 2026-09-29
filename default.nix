# Non-flake entry point: `nix-build`, `nix-env -f . -i`, or `import ./. { }`.
#
# nixpkgs is pinned to the exact revision in flake.lock, so flake and non-flake users
# build the same scanner versions.
{
  pkgs ?
    let
      lock = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${lock.owner}/${lock.repo}/archive/${lock.rev}.tar.gz";
      sha256 = lock.narHash;
    }) { },
  withScanners ? true,
  withAI ? false,
}:

pkgs.callPackage ./nix/package.nix { inherit withScanners withAI; }
