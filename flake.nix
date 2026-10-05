{
  description = "MeshCast (p2p-anycast) - Decentralized user-space ingress overlay mesh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      perSystem = flake-utils.lib.eachSystem [
        "x86_64-linux"
        "aarch64-linux"
      ] (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        {
          packages = {
            anycast-edge = pkgs.buildGoModule {
              pname = "anycast-edge";
              version = "0.3.2";
              src = ./.;
              subPackages = [ "cmd/anycast-edge" ];
              vendorHash = null;

              meta = with pkgs.lib; {
                description = "MeshCast decentralized edge router daemon";
                homepage = "https://github.com/kevinpthorne/p2p-anycast";
                license = licenses.asl20;
                mainProgram = "anycast-edge";
              };
            };

            anycast-origin = pkgs.buildGoModule {
              pname = "anycast-origin";
              version = "0.3.2";
              src = ./.;
              subPackages = [ "cmd/anycast-origin" ];
              vendorHash = null;

              meta = with pkgs.lib; {
                description = "MeshCast origin sidecar daemon";
                homepage = "https://github.com/kevinpthorne/p2p-anycast";
                license = licenses.asl20;
                mainProgram = "anycast-origin";
              };
            };

            anycast-ca = pkgs.buildGoModule {
              pname = "anycast-ca";
              version = "0.3.2";
              src = ./.;
              subPackages = [ "cmd/anycast-ca" ];
              vendorHash = null;

              meta = with pkgs.lib; {
                description = "MeshCast post-quantum CA CLI tool";
                homepage = "https://github.com/kevinpthorne/p2p-anycast";
                license = licenses.asl20;
                mainProgram = "anycast-ca";
              };
            };

            edge-image = pkgs.dockerTools.buildLayeredImage {
              name = "anycast-edge";
              tag = "latest";
              contents = [ ];
              fakeRootCommands = ''
                mkdir -p data tmp
                chmod 1777 tmp
              '';
              config = {
                Entrypoint = [ "${self.packages.${system}.anycast-edge}/bin/anycast-edge" ];
                WorkingDir = "/data";
                Volumes = {
                  "/data" = { };
                };
                ExposedPorts = {
                  "4002/udp" = { };
                };
              };
            };

            origin-image = pkgs.dockerTools.buildLayeredImage {
              name = "anycast-origin";
              tag = "latest";
              contents = [ ];
              fakeRootCommands = ''
                mkdir -p data tmp
                chmod 1777 tmp
              '';
              config = {
                Entrypoint = [ "${self.packages.${system}.anycast-origin}/bin/anycast-origin" ];
                WorkingDir = "/data";
                Volumes = {
                  "/data" = { };
                };
              };
            };

            default = self.packages.${system}.anycast-edge;
          };

          checks = pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.isLinux) {
            nixosModuleTest = import ./nix/checks/nixos-test.nix {
              inherit nixpkgs self system;
            };
          };

          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              go
              gopls
              protobuf
            ];
          };
        }
      );
    in
    perSystem
    // {
      overlays.default = final: prev: {
        anycast-edge = self.packages.${final.system}.anycast-edge;
        anycast-origin = self.packages.${final.system}.anycast-origin;
        anycast-ca = self.packages.${final.system}.anycast-ca;
      };

      nixosModules = {
        anycast-edge = import ./nix/modules/edge.nix self;
        anycast-origin = import ./nix/modules/origin.nix self;
        default =
          { ... }:
          {
            imports = [
              self.nixosModules.anycast-edge
              self.nixosModules.anycast-origin
            ];
          };
      };
    };
}
