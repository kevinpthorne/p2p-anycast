{ ... }:

{
  imports = [
    (import ./nix/modules/edge.nix {})
    (import ./nix/modules/origin.nix {})
  ];
}
