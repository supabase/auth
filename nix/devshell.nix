{ pkgs, ... }:
with pkgs;
mkShell {
  packages = [
    go
  ];
}
