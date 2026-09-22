firstArg:

let
  module =
    self:
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      cfg = config.services.anycast-edge;
      system = pkgs.stdenv.hostPlatform.system;
      defaultPackage =
        if self != null && self ? packages.${system}.anycast-edge then
          self.packages.${system}.anycast-edge
        else if pkgs ? anycast-edge then
          pkgs.anycast-edge
        else
          pkgs.callPackage ../packages/anycast-edge.nix { };

      listenUdpPort =
        let
          match = builtins.match ".*/udp/([0-9]+)/.*" cfg.listenP2P;
        in
        if match != null then [ (lib.toInt (builtins.head match)) ] else [ 4002 ];

      effectiveCaPub =
        if cfg.caPubKey != null then
          pkgs.writeText "ca.pub" cfg.caPubKey
        else if cfg.caPub != null then
          cfg.caPub
        else
          throw "services.anycast-edge: Either 'caPub' or 'caPubKey' must be specified.";
    in
    {
      imports = [
        (lib.mkAliasOptionModule [ "services" "p2p-anycast-edge" ] [ "services" "anycast-edge" ])
        (lib.mkAliasOptionModule [ "services" "p2p-anycast" "edge" ] [ "services" "anycast-edge" ])
      ];

      options.services.anycast-edge = {
        enable = lib.mkEnableOption "MeshCast Anycast Edge Router daemon";

        package = lib.mkOption {
          type = lib.types.package;
          default = defaultPackage;
          defaultText = lib.literalExpression "pkgs.anycast-edge";
          description = "The anycast-edge package to use.";
        };

        listenP2P = lib.mkOption {
          type = lib.types.str;
          default = "/ip4/0.0.0.0/udp/4002/quic-v1";
          description = "Multiaddr to listen for incoming QUIC connections from Origins.";
        };

        manifest = lib.mkOption {
          type = lib.types.either lib.types.path lib.types.str;
          description = "Path to Edge SignedCapabilityManifest (manifest.pb).";
        };

        caPub = lib.mkOption {
          type = lib.types.nullOr (lib.types.either lib.types.path lib.types.str);
          default = null;
          description = "Path to trusted Root CA public key (ca.pub PEM). Mutually exclusive with caPubKey.";
        };

        caPubKey = lib.mkOption {
          type = lib.types.nullOr lib.types.lines;
          default = null;
          description = "Inline PEM string of trusted Root CA public key. Mutually exclusive with caPub.";
        };

        identityKey = lib.mkOption {
          type = lib.types.str;
          default = "/var/lib/anycast-edge/identity.key";
          description = "Path to hardware or filesystem identity key.";
        };

        openFirewall = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Whether to automatically open the p2p QUIC UDP port in networking.firewall.";
        };

        openPorts = {
          tcp = lib.mkOption {
            type = lib.types.listOf lib.types.port;
            default = [ ];
            description = "Public TCP ingress ports to open in the firewall for forwarded services.";
          };
          udp = lib.mkOption {
            type = lib.types.listOf lib.types.port;
            default = [ ];
            description = "Public UDP ingress ports to open in the firewall for forwarded services.";
          };
        };

        extraArgs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Additional command-line arguments to pass to anycast-edge.";
        };
      };

      config = lib.mkIf cfg.enable {
        networking.firewall = lib.mkIf cfg.openFirewall {
          allowedUDPPorts = listenUdpPort ++ cfg.openPorts.udp;
          allowedTCPPorts = cfg.openPorts.tcp;
        };

        systemd.services.anycast-edge = {
          description = "MeshCast Anycast Edge Router Daemon";
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];

          serviceConfig = {
            ExecStart = lib.concatStringsSep " " (
              [
                "${cfg.package}/bin/anycast-edge"
                "--listen-p2p"
                (lib.escapeShellArg cfg.listenP2P)
                "--manifest"
                (lib.escapeShellArg (toString cfg.manifest))
                "--ca-pub"
                (lib.escapeShellArg (toString effectiveCaPub))
                "--identity-key"
                (lib.escapeShellArg cfg.identityKey)
              ]
              ++ map lib.escapeShellArg cfg.extraArgs
            );

            Restart = "always";
            RestartSec = "5s";
            StateDirectory = "anycast-edge";
            WorkingDirectory = "/var/lib/anycast-edge";
            LimitNOFILE = 65536;

            # Sandboxing and capabilities
            DynamicUser = true;
            AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
            CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
          };
        };
      };
    };
in
if firstArg ? config then (module null) firstArg else module firstArg
