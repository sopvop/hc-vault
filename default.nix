{ nixpkgs ? import <nixpkgs> {} } :
let
  ghc = nixpkgs.pkgs.haskell.packages.ghc8107;
  lib = nixpkgs.pkgs.haskell.lib;
  d = ghc.callPackage ./hc-vault-client.nix {};
  filterHaskell = builtins.filterSource (name: type:
  let base = builtins.baseNameOf name;
    in nixpkgs.lib.cleanSourceFilter name type &&
    (type != "directory" || (base != "dist" && base != "dist-newstyle")));
in lib.overrideCabal d (_ : { src = filterHaskell d.src; } )
