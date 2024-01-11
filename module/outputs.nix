{ lib, pkgs, ... }: {
  options.secretariaOutputs = lib.mkOption {
    type = lib.types.submodule {
      options = {
        uploadSecrets = lib.mkOption {
          type = lib.types.path;
          internal = true;
          description = ''
            script to upload secrets to the deployment server
          '';
          default = "${pkgs.coreutils}/bin/true";
        };
        extraFilesScript = lib.mkOption {
          type = lib.types.path;
          internal = true;
          description = ''
            script to generate nixos-anywhere ready directory
          '';
          default = "${pkgs.coreutils}/bin/true";
        };
        generateSecrets = lib.mkOption {
          type = lib.types.path;
          internal = true;
          description = ''
            script to generate secrets
          '';
          default = "${pkgs.coreutils}/bin/true";
        };
      };
    };
    description = ''
      utility outputs for secrets management of this machine
    '';
  };
}
