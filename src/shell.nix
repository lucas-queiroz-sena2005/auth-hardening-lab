{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    openssl
    sqlite
    docker
    docker-compose
    curl
  ];

  shellHook = ''
    echo "=== Security Prototype Development Environment ==="
    echo "Go version: $(go version)"
  '';
}
