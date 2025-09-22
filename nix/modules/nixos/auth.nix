{
  pkgs,
  lib,
  config,
  ...
}:
let
  cfg = config.services.auth;
  default_settings = rec {
    API_EXTERNAL_URL = "http://localhost:9999";
    DB_HOST = "localhost";
    DB_NAME = "postgres";
    DB_PASSWORD = "secret";
    DB_PORT = "5432";
    DB_USER = "supabase_auth_admin";
    DISABLE_SIGNUP = "false";
    DATABASE_URL = "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}";
    GOTRUE_API_EXTERNAL_URL = "http://localhost:9999";
    GOTRUE_DB_DRIVER = "postgres";
    GOTRUE_DB_HOST = DB_HOST;
    GOTRUE_DB_NAME = DB_NAME;
    GOTRUE_DB_PASSWORD = DB_PASSWORD;
    GOTRUE_DB_PORT = DB_PORT;
    GOTRUE_DB_USER = DB_USER;
    GOTRUE_DISABLE_SIGNUP = "false";
    GOTRUE_JWT_DEFAULT_GROUP_NAME = "authenticated";
    GOTRUE_JWT_EXP = "3600";
    GOTRUE_JWT_SECRET = "your-super-secret-jwt-token-with-at-least-32-characters-long";
    GOTRUE_MAILER_AUTOCONFIRM = "true";

    # Both v2 & v3 support reloading via signals, on linux this is SIGUSR1.
    GOTRUE_RELOADING_SIGNAL_ENABLED = "true";
    GOTRUE_RELOADING_SIGNAL_NUMBER = "10";

    # Both v2 & v3 disable the poller. While gotrue sets it to off by default we
    # defensively set it to false here.
    GOTRUE_RELOADING_POLLER_ENABLED = "false";

    # Determines how much idle time must pass before triggering a reload. This
    # ensures only 1 reload operation occurs during a burst of config updates.
    GOTRUE_RELOADING_GRACE_PERIOD_INTERVAL = "2s";

    # v3 does not use filesystem notifications for config reloads.
    GOTRUE_RELOADING_NOTIFY_ENABLED = "false";

    # TODO: remove duplicates?
    GOTRUE_SITE_URL = "http://localhost:3000";
    GOTRUE_SMTP_ADMIN_EMAIL = "admin@example.com";
    GOTRUE_SMTP_HOST = "localhost";
    GOTRUE_SMTP_PASS = "";
    GOTRUE_SMTP_PORT = "2500";
    GOTRUE_SMTP_SENDER_NAME = "Supabase";
    GOTRUE_SMTP_USER = "";
    JWT_DEFAULT_GROUP_NAME = "authenticated";
    JWT_EXP = "3600";
    JWT_SECRET = "your-super-secret-jwt-token-with-at-least-32-characters-long";
    MAILER_AUTOCONFIRM = "true";
    SITE_URL = "http://localhost:3000";
    SMTP_ADMIN_EMAIL = "admin@example.com";
    SMTP_HOST = "localhost";
    SMTP_PASS = "";
    SMTP_PORT = "2500";
    SMTP_SENDER_NAME = "Supabase";
    SMTP_USER = "";
  };
  auth_env = pkgs.writeText "auth.env" (
    lib.concatStringsSep "\n" (
      (lib.mapAttrsToList (name: value: "${name}=${value}") (default_settings // cfg.settings))
    )
  );
in
{
  options.services.auth = {
    enable = lib.mkEnableOption "Supabase Auth Service";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The Supabase Auth package to use.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9999;
      description = "Port to run the auth service on.";
    };

    settings = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Configuration settings for the auth service.";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = [ 9122 ];

    users.users.gotrue = {
      isSystemUser = true;
      description = "gotrue service user";
      group = "gotrue";
    };
    users.groups.gotrue = { };

    systemd.services.gotrue = {
      description = "gotrue (auth)";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "exec";
        WorkingDirectory = "/opt/gotrue";
        ExecStart = "${cfg.package}/bin/gotrue --config-dir /etc/auth.d";
        ExecReload = "${pkgs.coreutils}/bin/kill -10 $MAINPID";
        User = "gotrue";
        Restart = "always";
        RestartSec = 3;
        MemoryAccounting = true;
        MemoryMax = "50%";
        Slice = "services.slice";
        EnvironmentFile = [
          "/etc/gotrue/auth.env"
          "-/etc/gotrue.generated.env"
          "-/etc/gotrue.overrides.env"
        ];
        # preStart = ''
        #   pg_isready -h ${config.auth.settings.DB_HOST} -p ${config.auth.settings.DB_PORT} -U ${config.auth.settings.DB_USER}; do sleep 1; done
        # '';
      };
      unitConfig = {
        StartLimitIntervalSec = 10;
        StartLimitBurst = 5;
      };
    };

    systemd.tmpfiles.rules = [
      "d /etc/auth.d 0755 gotrue gotrue -"
      "d /opt/gotrue 0755 gotrue gotrue -"
      "C /etc/gotrue/auth.env 0440 gotrue gotrue - ${auth_env}"
    ];
  };
}

# TODO: initialization steps as activation script?
# - Wait for database to be ready:
#   until pg_isready -h ${config.auth.settings.DB_HOST} -p ${config.auth.settings.DB_PORT} -U ${config.auth.settings.DB_USER}; do sleep 1; done
# - Run migrations if they exist:
#   if [ -d migrations ]; then go run main.go migrate up; fi
