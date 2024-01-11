{
  perSystem =
    { pkgs
    , config
    , ...
    }: {
      devShells.default = pkgs.mkShell {
        packages = [
          config.treefmt.build.wrapper
        ];
      };
    };
}
