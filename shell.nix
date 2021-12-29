{ nixpkgs ? import <nixpkgs> {}}:
let
  d = import ./. { nixpkgs = nixpkgs; };
in (nixpkgs.pkgs.haskell.lib.addBuildTool d [nixpkgs.pkgs.haskellPackages.stylish-haskell nixpkgs.pkgs.vault]).env
