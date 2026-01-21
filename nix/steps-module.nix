{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.steps;
in {
  options.steps = {
    enable = mkEnableOption "Auth service initialization steps";

    commands = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Commands to run during service initialization.";
    };
  };

  config = mkIf cfg.enable {
    steps.commands = [
      # Wait for database to be ready
      #"until pg_isready -h ${config.auth.settings.DB_HOST} -p ${config.auth.settings.DB_PORT} -U ${config.auth.settings.DB_USER}; do sleep 1; done"
      # Run migrations if they exist
      #"if [ -d migrations ]; then go run main.go migrate up; fi"
    ];
  };
} 