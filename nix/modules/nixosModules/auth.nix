{
  pkgs,
  lib,
  config,
  ...
}:
let
  cfg = config.auth;
in
{
  options.auth = {
    enable = lib.mkEnableOption "Supabase Auth Service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../../package.nix { };
      description = "The Supabase Auth package to use.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9999;
      description = "Port to run the auth service on.";
    };

    settings = lib.mkOption {
      type = lib.types.attrs;
      default = {
        API_EXTERNAL_URL = "http://localhost:9999";
        DB_HOST = "localhost";
        DB_NAME = "postgres";
        DB_PASSWORD = "postgres";
        DB_PORT = "5432";
        DB_USER = "postgres";
        DISABLE_SIGNUP = "false";
        # TODO: should ENV vars be prefixed with GOTRUE_?
        # DATABASE_URL = "postgres://postgres:postgres@localhost:5432/postgres";
        # GOTRUE_API_EXTERNAL_URL = "http://localhost:9999";
        # GOTRUE_DB_DRIVER = "postgres";
        # GOTRUE_DB_HOST = "localhost";
        # GOTRUE_DB_NAME = "postgres";
        # GOTRUE_DB_PASSWORD = "postgres";
        # GOTRUE_DB_PORT = "5432";
        # GOTRUE_DB_USER = "postgres";
        # GOTRUE_DISABLE_SIGNUP = "false";
        # GOTRUE_JWT_DEFAULT_GROUP_NAME = "authenticated";
        # GOTRUE_JWT_EXP = "3600";
        # GOTRUE_JWT_SECRET = "your-super-secret-jwt-token-with-at-least-32-characters-long";
        # GOTRUE_MAILER_AUTOCONFIRM = "true";
        # GOTRUE_SITE_URL = "http://localhost:3000";
        # GOTRUE_SMTP_ADMIN_EMAIL = "admin@example.com";
        # GOTRUE_SMTP_HOST = "localhost";
        # GOTRUE_SMTP_PASS = "";
        # GOTRUE_SMTP_PORT = "2500";
        # GOTRUE_SMTP_SENDER_NAME = "Supabase";
        # GOTRUE_SMTP_USER = "";
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
      description = "Configuration settings for the auth service.";
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
        wantedBy = [ "system-manager.target" ];
        serviceConfig = {
          Type = "simple";
          WorkingDirectory = "/opt/gotrue";
          ExecStart = "${gotrue}/bin/gotrue --config-dir /etc/auth.d";
          User = "gotrue";
          Restart = "always";
          RestartSec = 3;
          MemoryAccounting = true;
          MemoryMax = "50%";
          Slice = "services.slice";
          EnvironmentFile = [
            # TODO: should the ENV file be provided by the module rather than the package?
            # cat > $out/etc/auth.env <<EOF
            # ${lib.concatStringsSep "\n" (
            #   lib.mapAttrsToList (name: value: "${name}=${value}") config.auth.settings
            # )}
            # EOF
            "${gotrue}/etc/auth.env"
            "-/etc/gotrue.generated.env"
            "-/etc/gotrue.overrides.env"
          ];
        };
      };

      systemd.tmpfiles.rules = [
        "d /etc/auth.d 0755 gotrue gotrue -"
        "d /etc/gotrue 0755 gotrue gotrue -"
        "d /opt/gotrue 0755 gotrue gotrue -"
      ];
    };
  };
}

# TODO: initialization steps as activation script?
# - Wait for database to be ready:
#   until pg_isready -h ${config.auth.settings.DB_HOST} -p ${config.auth.settings.DB_PORT} -U ${config.auth.settings.DB_USER}; do sleep 1; done
# - Run migrations if they exist:
#   if [ -d migrations ]; then go run main.go migrate up; fi
