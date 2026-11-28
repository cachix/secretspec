{
  config,
  lib,
  options,
  pkgs,
  ...
}:

let
  cfg = config.services.secretspec;

  plan = {
    schema = 1;
    manifest = toString cfg.manifest;
    profile = cfg.profile;
    runtime_dir = cfg.runtimeDir;
    cache_dir = cfg.cacheDir;
    credentials_dir = cfg.credentialsDir;
    systemd_creds = "${config.systemd.package}/bin/systemd-creds";
    systemctl = "${config.systemd.package}/bin/systemctl";
    path = lib.makeBinPath cfg.extraPackages;
    restart_units = cfg.restartUnits;
    secrets = lib.mapAttrsToList (name: secret: {
      inherit name;
      inherit (secret)
        owner
        group
        mode
        cache
        required
        units
        ;
    }) cfg.secrets;
    templates = lib.mapAttrsToList (name: template: {
      inherit name;
      inherit (template)
        content
        owner
        group
        mode
        units
        ;
    }) cfg.templates;
  };

  planFile = pkgs.writeText "secretspec-nixos-plan.json" (builtins.toJSON plan);

  refreshArgs = [
    "${cfg.package}/bin/secretspec"
    "nixos"
    "refresh"
    "--plan"
    (toString planFile)
  ]
  ++ [
    "--caller"
    "secretspec-nixos"
    "--caller-operation"
    "refresh"
  ]
  ++ lib.optionals (cfg.reason != null) [
    "--reason"
    cfg.reason
  ];
  refreshCommand = lib.escapeShellArgs refreshArgs;
  activationCommand = lib.escapeShellArgs (refreshArgs ++ [ "--no-restart" ]);

  units = lib.unique (
    lib.concatMap (secret: secret.units) (lib.attrValues cfg.secrets)
    ++ lib.concatMap (template: template.units) (lib.attrValues cfg.templates)
  );
in
{
  options.services.secretspec = {
    enable = lib.mkEnableOption "SecretSpec secret provisioning";

    package = lib.mkPackageOption pkgs "secretspec" { };

    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = ''
        Provider CLI tools made available to refresh, such as `pkgs.bws` for
        the Bitwarden Secrets Manager provider. They are added to the refresh
        service and activation-script `PATH`, and recorded in the plan so
        `secretspec nixos exec` and manual refresh use the same tools. They are
        not added to `environment.systemPackages`.
      '';
      example = lib.literalExpression "[ pkgs.bws ]";
    };

    manifest = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to the value-free `secretspec.toml` declaring the secrets.
        The manifest is copied to the Nix store, so it must not contain secret
        values or credentials.
      '';
      example = lib.literalExpression "./secretspec.toml";
    };

    profile = lib.mkOption {
      type = lib.types.str;
      default = "default";
      description = "SecretSpec profile to resolve.";
    };

    reason = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Access reason passed to providers that audit reads. Required by
        manifests whose `project.require_reason` policy is enabled.
      '';
      example = "NixOS system activation";
    };

    runtimeDir = lib.mkOption {
      type = lib.types.str;
      default = "/run/secretspec";
      description = ''
        tmpfs directory holding the current secret generation. Consumers should
        reference the read-only `secrets.<name>.path` or `templates.<name>.path`
        options rather than constructing paths.
      '';
    };

    cacheDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/secretspec/cache";
      description = ''
        Directory holding encrypted last-known-good values. It is used when a
        provider is unreachable so a reboot does not require vault access.
      '';
    };

    credentialsDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/secretspec/credentials";
      description = ''
        Directory holding host-sealed provider credentials created by
        `secretspec nixos link`.
      '';
    };

    refreshInterval = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Optional systemd timer interval for background refreshes, such as
        `"6h"`. The initial refresh still runs at activation (or from the
        systemd oneshot when `useSystemdActivation` is enabled).
      '';
      example = "6h";
    };

    useSystemdActivation = lib.mkOption {
      type = lib.types.bool;
      default =
        (options.systemd ? sysusers && config.systemd.sysusers.enable)
        || (options.services ? userborn && config.services.userborn.enable);
      defaultText = lib.literalExpression ''
        `systemd.sysusers.enable || services.userborn.enable`
      '';
      description = ''
        Run refresh from a systemd oneshot instead of a NixOS activation
        script. Defaults to true when systemd-sysusers or userborn manages
        users and groups, because the ordinary `users` activation script no
        longer creates them. Enable it explicitly when consumers need automatic
        restarts on switch, supervised unit status, or the systemd ordering
        benefits.
      '';
    };

    restartUnits = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Restart units declared by changed secrets and templates. This applies to
        systemd activation mode and manual/timer refreshes. The activation-script
        mode installs files only and does not restart units.
      '';
    };

    secrets = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule (
          { name, ... }: {
            options = {
              path = lib.mkOption {
                type = lib.types.str;
                readOnly = true;
                description = "Runtime path of the resolved value.";
                default = "${cfg.runtimeDir}/current/secrets/${name}";
              };

              cachePath = lib.mkOption {
                type = lib.types.str;
                readOnly = true;
                description = ''
                  Path of the host-encrypted cache entry. Use it with systemd's
                  `LoadCredentialEncrypted=` for an at-rest-encrypted credential.
                '';
                default = "${cfg.cacheDir}/${name}.cred";
              };

              placeholder = lib.mkOption {
                type = lib.types.str;
                readOnly = true;
                description = ''
                  Placeholder for `templates.<name>.content`. The refresh service
                  replaces it with the resolved value.
                '';
                default = "@secretspec:${name}@";
              };

              owner = lib.mkOption {
                type = lib.types.str;
                default = "root";
                description = "Owner of the runtime file.";
              };

              group = lib.mkOption {
                type = lib.types.str;
                default = "root";
                description = "Group of the runtime file.";
              };

              mode = lib.mkOption {
                type = lib.types.str;
                default = "0400";
                description = "Octal mode of the runtime file.";
              };

              cache = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Encrypt and retain the value for offline boots.";
              };

              required = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  Abort the refresh when this secret is missing and has no cached
                  value. Set to false for optional secrets.
                '';
              };

              units = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = ''
                  Full unit names restarted when this secret changes. In systemd
                  activation mode they are also ordered after
                  `secretspec.service`.
                '';
              };
            };
          }
        )
      );

      default = { };
      description = ''
        Secrets to provision. Each value becomes a file under
        `/run/secretspec/current/secrets/` and is available through
        `config.services.secretspec.secrets.<name>.path`.
      '';
    };

    templates = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule (
          { name, ... }: {
            options = {
              path = lib.mkOption {
                type = lib.types.str;
                readOnly = true;
                description = "Runtime path of the rendered template.";
                default = "${cfg.runtimeDir}/current/templates/${name}";
              };

              content = lib.mkOption {
                type = lib.types.str;
                description = ''
                  Template text. Use
                  `config.services.secretspec.secrets.<name>.placeholder` for
                  values that must not enter the Nix store.
                '';
              };

              owner = lib.mkOption {
                type = lib.types.str;
                default = "root";
                description = "Owner of the rendered template.";
              };

              group = lib.mkOption {
                type = lib.types.str;
                default = "root";
                description = "Group of the rendered template.";
              };

              mode = lib.mkOption {
                type = lib.types.str;
                default = "0400";
                description = "Octal mode of the rendered template.";
              };

              units = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = "Units restarted when this template changes.";
              };
            };
          }
        )
      );

      default = { };
      description = ''
        Rendered configuration files for programs that cannot consume a plain
        runtime file directly. Templates are written to
        `/run/secretspec/current/templates/`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.match "[A-Za-z_][A-Za-z0-9_]*" cfg.profile != null;
        message = "services.secretspec.profile must be a simple profile name";
      }
      {
        assertion = builtins.intersectAttrs cfg.secrets cfg.templates == { };
        message = "services.secretspec secret and template names must not collide";
      }
    ]
    ++ lib.concatLists (
      lib.mapAttrsToList (name: _: [
        {
          assertion = builtins.match "[A-Za-z_][A-Za-z0-9_]*" name != null;
          message = "services.secretspec secret name '${name}' is not a valid SecretSpec key";
        }
      ]) cfg.secrets
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (name: template: [
        {
          assertion = builtins.match "[A-Za-z0-9._-]+" name != null;
          message = "services.secretspec template name '${name}' is not a valid filename";
        }
        {
          assertion = builtins.match "0[0-7]{3}" template.mode != null;
          message = "services.secretspec.templates.${name}.mode must be an octal mode such as 0400";
        }
      ]) cfg.templates
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (name: secret: [
        {
          assertion = builtins.match "0[0-7]{3}" secret.mode != null;
          message = "services.secretspec.secrets.${name}.mode must be an octal mode such as 0400";
        }
      ]) cfg.secrets
    );

    environment.etc."secretspec/plan.json".source = planFile;

    environment.systemPackages = [ cfg.package ];

    system.activationScripts.secretspec = lib.mkIf (!cfg.useSystemdActivation) {
      deps = [
        "specialfs"
        "users"
        "groups"
      ];
      text = ''
        export PATH=${
          lib.makeBinPath (
            [
              config.systemd.package
              pkgs.coreutils
            ]
            ++ cfg.extraPackages
          )
        }:$PATH
        ${activationCommand}
      '';
    };

    warnings =
      lib.optional (units != [ ] && !cfg.useSystemdActivation)
        "services.secretspec: units are configured but useSystemdActivation is false; activation mode installs secrets without restarting units. Enable systemd activation or run `secretspec nixos refresh` to restart consumers.";

    systemd.tmpfiles.rules = lib.unique (
      [
        "d ${cfg.runtimeDir} 0755 root root -"
        "d ${cfg.cacheDir} 0700 root root -"
        "d ${cfg.credentialsDir} 0700 root root -"
      ]
      ++ lib.optional (dirOf cfg.cacheDir != "/") "d ${dirOf cfg.cacheDir} 0755 root root -"
      ++ lib.optional (dirOf cfg.credentialsDir != "/") "d ${dirOf cfg.credentialsDir} 0755 root root -"
    );

    systemd.services = lib.mkMerge (
      [
        {
          secretspec = {
            description = "Provision SecretSpec secrets";
            wantedBy = lib.optional cfg.useSystemdActivation "multi-user.target";
            after = [
              "local-fs.target"
            ]
            ++ lib.optional (
              options.systemd ? sysusers && config.systemd.sysusers.enable
            ) "systemd-sysusers.service"
            ++ lib.optional (options.services ? userborn && config.services.userborn.enable) "userborn.service";
            path = [
              config.systemd.package
              pkgs.coreutils
            ]
            ++ cfg.extraPackages;
            serviceConfig = {
              Type = "oneshot";
              ExecStart = refreshCommand;
              UMask = "0077";
              NoNewPrivileges = true;
              PrivateTmp = true;
              ProtectHome = true;
              ProtectSystem = "strict";
              ProtectKernelTunables = true;
              ProtectKernelModules = true;
              ProtectControlGroups = true;
              RestrictAddressFamilies = [
                "AF_UNIX"
                "AF_INET"
                "AF_INET6"
              ];
              ReadWritePaths = [
                cfg.runtimeDir
                cfg.cacheDir
                cfg.credentialsDir
              ];
            };
          };
        }
      ]
      ++ lib.optionals cfg.useSystemdActivation [
        (lib.genAttrs (map (unit: lib.removeSuffix ".service" unit) units) (unit: {
          # nix-daemon must still start when provisioning fails: otherwise a
          # bad credential leaves no working Nix to repair the system with.
          requires = lib.optional (unit != "nix-daemon") "secretspec.service";
          wants = lib.optional (unit == "nix-daemon") "secretspec.service";
          after = [ "secretspec.service" ];
        }))
      ]
    );

    systemd.timers.secretspec = lib.mkIf (cfg.refreshInterval != null) {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        Unit = "secretspec.service";
        OnBootSec = "5m";
        OnUnitActiveSec = cfg.refreshInterval;
      };
    };
  };
}
