{ config, lib, pkgs, ... }:
let
  cfg = config.secretaria;
  
  secretsDir = cfg.repoDir + "/sops/secrets";
  groupsDir = cfg.repoDir + "/sops/groups";

  # My symlink is in the nixos module detected as a directory also it works in the repl. Is this because of pure evaluation?
  containsSymlink = path:
    builtins.pathExists path && (builtins.readFileType path == "directory" || builtins.readFileType path == "symlink");

  containsMachine = parent: name: type:
    type == "directory" && containsSymlink "${parent}/${name}/machines/${cfg.machineName}";

  containsMachineOrGroups = name: type:
    (containsMachine secretsDir name type) || lib.any (group: type == "directory" && containsSymlink "${secretsDir}/${name}/groups/${group}") groups;

  filterDir = filter: dir:
    lib.optionalAttrs (builtins.pathExists dir)
      (lib.filterAttrs filter (builtins.readDir dir));

  groups = builtins.attrNames (filterDir (containsMachine groupsDir) groupsDir);
  secrets = filterDir containsMachineOrGroups secretsDir;

  #Only machine specific secrets
  secretsFilteredDir = lib.sources.sourceByRegex secretsDir (
    (lib.mapAttrsToList (name: _:  "${name}") secrets)
    ++ (lib.mapAttrsToList (name: _:  "${name}/secret") secrets)
  );
in
{
  config = lib.mkIf (cfg.secretStore == "sops") {
    secretaria.secretsDirectory = "/run/secrets";
    secretaria.secretsPrefix = cfg.machineName + "-";
    secretariaOutputs = lib.mkIf (cfg.secrets != { }) {

      generateSecrets = let
        jsonConfig = pkgs.writers.writeJSON "secretaria.json" {
          machine_name = cfg.machineName;
          secret_submodules = lib.mapAttrs (_name: secret: {
            secrets = builtins.attrNames secret.secrets;
            facts = lib.mapAttrs (_: secret: secret.path) secret.facts;
            generator = secret.generator.finalScript;
          }) cfg.secrets;
        };
      in pkgs.writeScript "generate-secrets" ''
        #!/usr/bin/env bash
        set -x
        export REPO_DIR=${cfg.repoDirWritable}
        ${pkgs.python3}/bin/python3 ${./sops-generate.py} --debug --json ${jsonConfig}
      ''; 

      uploadSecrets = pkgs.writeScript "upload-secrets" ''
        #!${pkgs.python3}/bin/python
        import json
        import sys
        from clan_cli.secrets.sops_generate import upload_age_key_from_nix
        # the second toJSON is needed to escape the string for the python
        args = json.loads(${builtins.toJSON (builtins.toJSON { machine_name = cfg.machineName; })})
        upload_age_key_from_nix(**args)
      '';

      extraFilesScript = pkgs.writeScript "extra-files-secrets" ''
        #!/usr/bin/env bash
        set -efu

        umask 0077

        PATH=${lib.makeBinPath [
          pkgs.sops
        ]}:$PATH

        mkdir -p .${cfg.secretsUploadDirectory}
        sops --config /dev/null --decrypt ${secretsDir}/${cfg.machineName}-age.key/secret > .${cfg.secretsUploadDirectory}/key.txt
      '';
    };
    sops.secrets = builtins.mapAttrs
      (name: _: {
        sopsFile = secretsFilteredDir + "/${name}/secret";
        format = "binary";
      })
      secrets;
    # To get proper error messages about missing secrets we need a dummy secret file that is always present
    sops.defaultSopsFile = lib.mkIf config.sops.validateSopsFiles (lib.mkDefault (builtins.toString (pkgs.writeText "dummy.yaml" "")));

    sops.age.keyFile = lib.mkIf (builtins.pathExists (cfg.repoDir + "/sops/secrets/${cfg.machineName}-age.key/secret"))
      (lib.mkDefault "/var/lib/sops-nix/key.txt");
    secretaria.secretsUploadDirectory = lib.mkDefault "/var/lib/sops-nix";
  };
}
