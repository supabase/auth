{
  pkgs,
  flake,
  perSystem,
  ...
}:
flake.inputs.nixpkgs.lib.nixos.runTest {
  name = "auth";
  hostPkgs = pkgs;
  node.specialArgs = { inherit flake perSystem; };
  nodes.server =
    { config, ... }:
    {
      imports = [
        (import flake.nixosModules.auth)
      ];

      virtualisation = {
        forwardPorts = [
          {
            from = "host";
            host.port = 13022;
            guest.port = 22;
          }
        ];
      };
      services.openssh = {
        enable = true;
      };

      services.auth.enable = true;

      services.postgresql = {
        enable = true;
        enableTCPIP = true;
        initialScript = pkgs.writeText "init-postgres-with-password" ''
          CREATE USER supabase_admin LOGIN CREATEROLE CREATEDB REPLICATION BYPASSRLS;

          -- Supabase super admin
          CREATE USER supabase_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION PASSWORD 'secret';
          CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION supabase_auth_admin;
          GRANT CREATE ON DATABASE postgres TO supabase_auth_admin;
          ALTER USER supabase_auth_admin SET search_path = 'auth';
        '';
        authentication = ''
          host supabase_auth_admin postgres samenet scram-sha-256
        '';
      };
    };
  testScript =
    { nodes, ... }:
    ''
      start_all()

      server.wait_for_unit("multi-user.target")
      server.wait_for_unit("postgresql.service")

      server.wait_for_unit("gotrue.service")
    '';
}
