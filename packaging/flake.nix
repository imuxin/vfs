{
  description = "vfs object storage";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  outputs = { self, nixpkgs }:
    let
      system = "aarch64-darwin";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "vfs";
        version = "0.1.0";
        src = ../.;
        buildInputs = [ pkgs.vlang ];
        buildPhase = "v -o vfs cmd/vfs";
        installPhase = "install -Dm755 vfs $out/bin/vfs";
      };
    };
}
