{
  nixpkgs,
  self,
  system,
}:

let
  pkgs = import nixpkgs { inherit system; };
  eval = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      (
        { pkgs, ... }:
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "/dev/null";
            fsType = "ext4";
          };

          services.anycast-edge = {
            enable = true;
            manifest = pkgs.writeText "manifest.pb" "dummy";
            caPub = pkgs.writeText "ca.pub" "dummy";
          };

          services.anycast-origin = {
            enable = true;
            manifest = pkgs.writeText "manifest.pb" "dummy";
            caPub = pkgs.writeText "ca.pub" "dummy";
            settings = {
              edge_multiaddrs = [ "/ip4/127.0.0.1/udp/4002/quic-v1" ];
              origin_master_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
              services = [
                {
                  service_id = "test-service";
                  protocol = "TCP";
                  public_port = 8080;
                  policy = "CLUSTERED_RTT";
                  target = "127.0.0.1:8080";
                }
              ];
            };
          };
        }
      )
    ];
  };
in
# Return the systemd service config to verify evaluation succeeds
pkgs.runCommand "nixos-module-test"
  {
    edgeService = eval.config.systemd.services.anycast-edge.serviceConfig.ExecStart;
    originService = eval.config.systemd.services.anycast-origin.serviceConfig.ExecStart;
  }
  ''
    echo "Edge service ExecStart: $edgeService"
    echo "Origin service ExecStart: $originService"
    touch $out
  ''
