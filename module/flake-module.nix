{ inputs, ... }: {
  flake.nixosModules = {
    secretaria.imports = [
      inputs.sops-nix.nixosModules.sops
      ./secrets.nix
      ./outputs.nix
    ];
  };
}
