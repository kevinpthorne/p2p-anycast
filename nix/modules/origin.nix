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

  effectiveManifest =
    if cfg.manifestKey != null then
      pkgs.writeText "manifest.pb" cfg.manifestKey
    else if cfg.manifest != null then
      cfg.manifest
    else
      throw "services.anycast-origin: Either 'manifest' or 'manifestKey' must be specified.";
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
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to Origin SignedCapabilityManifest file (binary .pb or base64 text). Mutually exclusive with manifestKey.";
    };

    manifestKey = lib.mkOption {
      type = lib.types.nullOr lib.types.lines;
      default = null;
      description = "Inline base64-encoded SignedCapabilityManifest string. Mutually exclusive with manifest.";
    };

    caPub = lib.mkOption {
      type = lib.types.path;
      description = "Path to trusted Root CA public key (ca.pub PEM).";
    };

    identityKey = lib.mkOption {
      type = lib.types.either lib.types.path lib.types.str;
      default = "/var/lib/anycast-origin/identity.key";
      description = "Path to hardware or filesystem identity key file, or inline PEM private key string.";
    };

    dynamicUser = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to run the service under a dynamic user. Set to false if reading keys owned by root.";
    };

    user = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "User to run the daemon as when dynamicUser is false.";
    };

    group = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Group to run the daemon as when dynamicUser is false.";
    };

    masterKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to a file containing the Origin master key in hex. Required.";
    };

    extraCredentials = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Additional systemd LoadCredential specifications to pass to the service.";
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
          "--manifest" (lib.escapeShellArg effectiveManifest)
          "--ca-pub" (lib.escapeShellArg cfg.caPub)
          "--identity-key" (lib.escapeShellArg (toString cfg.identityKey))
        ] ++ lib.optional (cfg.masterKeyFile != null) "--master-key-file ${lib.escapeShellArg cfg.masterKeyFile}"
          ++ map lib.escapeShellArg cfg.extraArgs);

        Restart = "always";
        RestartSec = "5s";
        StateDirectory = "anycast-origin";
        WorkingDirectory = "/var/lib/anycast-origin";
        LimitNOFILE = 65536;

        # Sandboxing
        DynamicUser = cfg.dynamicUser;
        User = lib.mkIf (!cfg.dynamicUser && cfg.user != null) cfg.user;
        Group = lib.mkIf (!cfg.dynamicUser && cfg.group != null) cfg.group;
        LoadCredential =
          cfg.extraCredentials
          ++ lib.optional (
            cfg.dynamicUser
            && (toString cfg.identityKey) != "/var/lib/anycast-origin/identity.key"
            && !lib.hasPrefix "-----BEGIN" (toString cfg.identityKey)
          ) "identity.key:${toString cfg.identityKey}"
          ++ lib.optional (
            cfg.dynamicUser
            && cfg.masterKeyFile != null
          ) "master.key:${toString cfg.masterKeyFile}";
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
      };
    };
  };
}
