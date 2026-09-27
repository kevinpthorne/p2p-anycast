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

      effectiveManifest =
        if cfg.manifestKey != null then
          pkgs.writeText "manifest.pb" cfg.manifestKey
        else if cfg.manifest != null then
          cfg.manifest
        else
          throw "services.anycast-edge: Either 'manifest' or 'manifestKey' must be specified.";
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
          type = lib.types.nullOr (lib.types.either lib.types.path lib.types.str);
          default = null;
          description = "Path to Edge SignedCapabilityManifest file (binary .pb or base64 text). Mutually exclusive with manifestKey.";
        };

        manifestKey = lib.mkOption {
          type = lib.types.nullOr lib.types.lines;
          default = null;
          description = "Inline base64-encoded SignedCapabilityManifest string. Mutually exclusive with manifest.";
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

        dynamicFirewall = {
          enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Whether to automatically open and close forwarded service ports dynamically in the firewall as services are registered or evicted.";
          };

          backend = lib.mkOption {
            type = lib.types.enum [ "auto" "iptables" "nftables" "none" ];
            default = "auto";
            description = "Firewall backend to use for dynamic port management.";
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
          extraCommands = lib.mkIf cfg.dynamicFirewall.enable ''
            ip46tables -N ANYCAST-EDGE 2>/dev/null || true
            ip46tables -C nixos-fw -j ANYCAST-EDGE 2>/dev/null || ip46tables -I nixos-fw 1 -j ANYCAST-EDGE 2>/dev/null || true
          '';
          extraStopCommands = lib.mkIf cfg.dynamicFirewall.enable ''
            ip46tables -D nixos-fw -j ANYCAST-EDGE 2>/dev/null || true
            ip46tables -F ANYCAST-EDGE 2>/dev/null || true
            ip46tables -X ANYCAST-EDGE 2>/dev/null || true
          '';
        };

        systemd.services.anycast-edge = {
          description = "MeshCast Anycast Edge Router Daemon";
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          path = [
            pkgs.iptables
            pkgs.nftables
            pkgs.iproute2
          ];

          serviceConfig = {
            ExecStart = lib.concatStringsSep " " (
              [
                "${cfg.package}/bin/anycast-edge"
                "--listen-p2p"
                (lib.escapeShellArg cfg.listenP2P)
                "--manifest"
                (lib.escapeShellArg (toString effectiveManifest))
                "--ca-pub"
                (lib.escapeShellArg (toString effectiveCaPub))
                "--identity-key"
                (lib.escapeShellArg cfg.identityKey)
                "--firewall"
                (lib.escapeShellArg (if cfg.dynamicFirewall.enable then cfg.dynamicFirewall.backend else "none"))
              ]
              ++ map lib.escapeShellArg cfg.extraArgs
            );

            Restart = "always";
            RestartSec = "5s";
            RuntimeDirectory = "anycast-edge";
            StateDirectory = "anycast-edge";
            WorkingDirectory = "/var/lib/anycast-edge";
            LimitNOFILE = 65536;

            Environment = [
              "XTABLES_LOCKFILE=/run/anycast-edge/xtables.lock"
            ];

            # Sandboxing and capabilities
            DynamicUser = true;
            AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ] ++ lib.optional cfg.dynamicFirewall.enable "CAP_NET_ADMIN";
            CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ] ++ lib.optional cfg.dynamicFirewall.enable "CAP_NET_ADMIN";
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
          };
        };
      };
    };
in
if firstArg ? config then (module null) firstArg else module firstArg
