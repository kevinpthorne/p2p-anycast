self: { config, lib, pkgs, ... }:

let
  cfg = config.services.anycast-origin;
  defaultPackage = if self ? packages.${pkgs.system}.anycast-origin
                   then self.packages.${pkgs.system}.anycast-origin
                   else pkgs.callPackage ../packages/anycast-origin.nix {};

  format = pkgs.formats.json {};
  generatedConfigFile = if cfg.settings != null
                        then format.generate "origin-config.json" cfg.settings
                        else null;

  effectiveConfigFile = if cfg.configFile != null
                        then cfg.configFile
                        else generatedConfigFile;
in
{
  options.services.anycast-origin = {
    enable = lib.mkEnableOption "MeshCast Anycast Origin Sidecar daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      description = "The anycast-origin package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to origin JSON configuration file.
        If null, configuration will be generated from services.anycast-origin.settings.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule {
        freeformType = format.type;
        options = {
          edge_multiaddrs = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            description = "List of Edge multiaddrs to connect to.";
          };
          origin_master_key = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "Origin 256-bit master key in hex (for HMAC token generation).";
          };
          services = lib.mkOption {
            type = lib.types.listOf (lib.types.submodule {
              options = {
                service_id = lib.mkOption {
                  type = lib.types.str;
                  description = "Identifier for the service.";
                };
                protocol = lib.mkOption {
                  type = lib.types.enum [ "TCP" "UDP" "TCP_AND_UDP" ];
                  default = "TCP";
                  description = "Transport protocol.";
                };
                public_port = lib.mkOption {
                  type = lib.types.port;
                  description = "Public port requested on the Edge.";
                };
                policy = lib.mkOption {
                  type = lib.types.enum [ "CLUSTERED_RTT" "TLS_SNI" "FAILOVER_STANDBY" "STRICT_SINGLETON" ];
                  default = "CLUSTERED_RTT";
                  description = "Routing policy for this service.";
                };
                sni_hostname = lib.mkOption {
                  type = lib.types.str;
                  default = "";
                  description = "SNI hostname (required if policy is TLS_SNI).";
                };
                target = lib.mkOption {
                  type = lib.types.str;
                  description = "Target address (host:port, cluster FQDN, or unix:///path).";
                };
                enable_proxy_protocol = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Whether to inject PROXYv2 binary header on TCP streams.";
                };
              };
            });
            default = [];
            description = "List of backend services to register and forward.";
          };
        };
      });
      default = null;
      description = ''
        Structured configuration for anycast-origin.
        Ignored if services.anycast-origin.configFile is specified.
      '';
    };

    manifest = lib.mkOption {
      type = lib.types.path;
      description = "Path to Origin SignedCapabilityManifest (origin_manifest.pb).";
    };

    caPub = lib.mkOption {
      type = lib.types.path;
      description = "Path to trusted Root CA public key (ca.pub PEM).";
    };

    identityKey = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/anycast-origin/identity.key";
      description = "Path to hardware or filesystem identity key.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Additional command-line arguments to pass to anycast-origin.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configFile != null || cfg.settings != null;
        message = "Either services.anycast-origin.configFile or services.anycast-origin.settings must be specified.";
      }
    ];

    systemd.services.anycast-origin = {
      description = "MeshCast Anycast Origin Sidecar Daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " ([
          "${cfg.package}/bin/anycast-origin"
          "--config" (lib.escapeShellArg effectiveConfigFile)
          "--manifest" (lib.escapeShellArg cfg.manifest)
          "--ca-pub" (lib.escapeShellArg cfg.caPub)
          "--identity-key" (lib.escapeShellArg cfg.identityKey)
        ] ++ map lib.escapeShellArg cfg.extraArgs);

        Restart = "always";
        RestartSec = "5s";
        StateDirectory = "anycast-origin";
        WorkingDirectory = "/var/lib/anycast-origin";
        LimitNOFILE = 65536;

        # Sandboxing
        DynamicUser = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
      };
    };
  };
}
