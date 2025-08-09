{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.auth;
in {
  options.auth = {
    enable = mkEnableOption "Supabase Auth Service";

    package = mkOption {
      type = types.package;
      description = "The Supabase Auth package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 9999;
      description = "Port to run the auth service on.";
    };

    settings = mkOption {
      type = types.attrs;
      default = {
        SITE_URL = "http://localhost:3000";
        API_EXTERNAL_URL = "http://localhost:9999";
        DB_HOST = "localhost";
        DB_PORT = "5432";
        DB_NAME = "postgres";
        DB_USER = "postgres";
        DB_PASSWORD = "postgres";
        JWT_SECRET = "your-super-secret-jwt-token-with-at-least-32-characters-long";
        JWT_EXP = "3600";
        JWT_DEFAULT_GROUP_NAME = "authenticated";
        DISABLE_SIGNUP = "false";
        MAILER_AUTOCONFIRM = "true";
        SMTP_ADMIN_EMAIL = "admin@example.com";
        SMTP_HOST = "localhost";
        SMTP_PORT = "2500";
        SMTP_USER = "";
        SMTP_PASS = "";
        SMTP_SENDER_NAME = "Supabase";
      };
      description = "Configuration settings for the auth service.";
    };
  };

  config = mkIf cfg.enable {
    # No NixOS-specific options here
  };
} 