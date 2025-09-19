{ pkgs, ... }:
pkgs.buildGoModule {
  pname = "supabase-auth";
  version = "2.180.0";
  src = ./..;

  vendorHash = "sha256-knYvNkEVffWisvb4Dhm5qqtqQ4co9MGoNt6yH6dUll8=";

  buildFlags = [
    "-tags"
    "netgo"
  ];

  # we cannot run test in the sandbox as tests rely on postgresql tcp connection
  doCheck = false;

  subPackages = [ "." ];

  postInstall = ''
    mv $out/bin/auth $out/bin/gotrue
  '';
}
