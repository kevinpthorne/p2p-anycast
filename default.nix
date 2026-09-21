{ pkgs ? import <nixpkgs> { } }:

pkgs.callPackage ./nix/packages/p2p-anycast.nix { }
