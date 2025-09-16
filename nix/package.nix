{ pkgs, ... }:
pkgs.buildGoModule {
  pname = "supabase-auth";
  version = "0.1.0";
  src = ./..;

  vendorHash = "sha256-knYvNkEVffWisvb4Dhm5qqtqQ4co9MGoNt6yH6dUll8=";

  buildFlags = [
    "-tags"
    "netgo"
  ];
  doCheck = false;

  subPackages = [ "." ];

  postInstall = ''
    mv $out/bin/auth $out/bin/gotrue
  '';
}
