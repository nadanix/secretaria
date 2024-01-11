import argparse
import logging
import json
import os
import sys
import subprocess
import shutil
import shlex
from pathlib import Path
from typing import Any, IO
from tempfile import NamedTemporaryFile, TemporaryDirectory
from collections.abc import Callable, Iterator
from contextlib import contextmanager

log = logging.getLogger(__name__)

class ClanError(Exception):
    """Base class for exceptions in this module."""

    pass

class SopsKey:
    def __init__(self, pubkey: str, username: str) -> None:
        self.pubkey = pubkey
        self.username = username

def has_secret(flake_dir: Path, secret: str) -> bool:
    return (sops_secrets_folder(flake_dir) / secret / "secret").exists()

def allow_member(
    group_folder: Path, source_folder: Path, name: str, do_update_keys: bool = True
) -> None:
    source = source_folder / name
    if not source.exists():
        msg = f"{name} does not exist in {source_folder}: "
        msg += list_directory(source_folder)
        raise ClanError(msg)
    group_folder.mkdir(parents=True, exist_ok=True)
    user_target = group_folder / name
    if user_target.exists():
        if not user_target.is_symlink():
            raise ClanError(
                f"Cannot add user {name}. {user_target} exists but is not a symlink"
            )
        os.remove(user_target)

    user_target.symlink_to(os.path.relpath(source, user_target.parent))
    if do_update_keys:
        update_keys(
            group_folder.parent,
            list(sorted(collect_keys_for_path(group_folder.parent))),
        )
        
def collect_keys_for_type(folder: Path) -> set[str]:
    if not folder.exists():
        return set()
    keys = set()
    for p in folder.iterdir():
        if not p.is_symlink():
            continue
        try:
            target = p.resolve()
        except FileNotFoundError:
            tty.warn(f"Ignoring broken symlink {p}")
            continue
        kind = target.parent.name
        if folder.name != kind:
            tty.warn(f"Expected {p} to point to {folder} but points to {target.parent}")
            continue
        keys.add(read_key(target))
    return keys

def collect_keys_for_path(path: Path) -> set[str]:
    keys = set([])
    keys.update(collect_keys_for_type(path / "machines"))
    keys.update(collect_keys_for_type(path / "users"))
    groups = path / "groups"
    if not groups.is_dir():
        return keys
    for group in groups.iterdir():
        keys.update(collect_keys_for_type(group / "machines"))
        keys.update(collect_keys_for_type(group / "users"))
    return keys
        
def read_key(path: Path) -> str:
    with open(path / "key.json") as f:
        try:
            key = json.load(f)
        except json.JSONDecodeError as e:
            raise ClanError(f"Failed to decode {path.name}: {e}")
    if key["type"] != "age":
        raise ClanError(
            f"{path.name} is not an age key but {key['type']}. This is not supported"
        )
    publickey = key.get("publickey")
    if not publickey:
        raise ClanError(f"{path.name} does not contain a public key")
    return publickey

def nix_command(flags: list[str]) -> list[str]:
    return ["nix", "--extra-experimental-features", "nix-command flakes", *flags]

def nixpkgs_flake() -> Path:
    return (module_root()).resolve()

def module_root() -> Path:
    return Path(os.environ.get("PRJ_ROOT"))
        
def nix_shell(packages: list[str], cmd: list[str]) -> list[str]:
    # we cannot use nix-shell inside the nix sandbox
    # in our tests we just make sure we have all the packages
    if os.environ.get("IN_NIX_SANDBOX"):
        return cmd
    return [
        *nix_command(
            [
                "shell",
                "--inputs-from",
                f"{nixpkgs_flake()!s}",
            ]
        ),
        *packages,
        "-c",
        *cmd,
    ]

def get_public_key(privkey: str) -> str:
    cmd = nix_shell(["nixpkgs#age"], ["age-keygen", "-y"])
    try:
        res = subprocess.run(
            cmd, input=privkey, stdout=subprocess.PIPE, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        raise ClanError(
            "Failed to get public key for age private key. Is the key malformed?"
        ) from e
    return res.stdout.strip()

def machines_folder(flake_dir: Path, group: str) -> Path:
    return sops_secrets_folder(flake_dir) / group / "machines"

def users_folder(flake_dir: Path, group: str) -> Path:
    return sops_secrets_folder(flake_dir) / group / "users"

def groups_folder(flake_dir: Path, group: str) -> Path:
    return sops_secrets_folder(flake_dir) / group / "groups"

@contextmanager
def sops_manifest(keys: list[str]) -> Iterator[Path]:
    with NamedTemporaryFile(delete=False, mode="w") as manifest:
        json.dump(
            dict(creation_rules=[dict(key_groups=[dict(age=keys)])]), manifest, indent=2
        )
        manifest.flush()
        yield Path(manifest.name)

def add_machine(flake_dir: Path, name: str, key: str, force: bool) -> None:
    write_key(sops_machines_folder(flake_dir) / name, key, force)

def has_machine(flake_dir: Path, name: str) -> bool:
    return (sops_machines_folder(flake_dir) / name / "key.json").exists()

def write_key(path: Path, publickey: str, overwrite: bool) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        if not overwrite:
            flags |= os.O_EXCL
        fd = os.open(path / "key.json", flags)
    except FileExistsError:
        raise ClanError(f"{path.name} already exists in {path}")
    with os.fdopen(fd, "w") as f:
        json.dump({"publickey": publickey, "type": "age"}, f, indent=2)

def get_sops_folder(flake_dir: Path) -> Path:
    return flake_dir / "sops"


def gen_sops_subfolder(subdir: str) -> Callable[[Path], Path]:
    def folder(flake_dir: Path) -> Path:
        return flake_dir / "sops" / subdir

    return folder


sops_secrets_folder = gen_sops_subfolder("secrets")
sops_users_folder = gen_sops_subfolder("users")
sops_machines_folder = gen_sops_subfolder("machines")
sops_groups_folder = gen_sops_subfolder("groups")

def default_sops_key_path() -> Path:
    raw_path = os.environ.get("SOPS_AGE_KEY_FILE")
    if raw_path:
        return Path(raw_path)
    else:
        return user_config_dir() / "sops" / "age" / "keys.txt"
        
def ensure_sops_key(flake_dir: Path) -> SopsKey:
    key = os.environ.get("SOPS_AGE_KEY")
    if key:
        return ensure_user_or_machine(flake_dir, get_public_key(key))
    path = default_sops_key_path()
    if path.exists():
        return ensure_user_or_machine(flake_dir, get_public_key(path.read_text()))
    else:
        raise ClanError(
            "No sops key found. Please generate one with 'clan secrets key generate'."
        )
        
def encrypt_file(
    secret_path: Path, content: IO[str] | str | None, keys: list[str]
) -> None:
    folder = secret_path.parent
    folder.mkdir(parents=True, exist_ok=True)

    with sops_manifest(keys) as manifest:
        if not content:
            args = ["sops", "--config", str(manifest)]
            args.extend([str(secret_path)])
            cmd = nix_shell(["nixpkgs#sops"], args)
            p = subprocess.run(cmd)
            # returns 200 if the file is changed
            if p.returncode != 0 and p.returncode != 200:
                raise ClanError(
                    f"Failed to encrypt {secret_path}: sops exited with {p.returncode}"
                )
            return

        # hopefully /tmp is written to an in-memory file to avoid leaking secrets
        with NamedTemporaryFile(delete=False) as f:
            try:
                with open(f.name, "w") as fd:
                    if isinstance(content, str):
                        fd.write(content)
                    else:
                        shutil.copyfileobj(content, fd)
                # we pass an empty manifest to pick up existing configuration of the user
                args = ["sops", "--config", str(manifest)]
                args.extend(["-i", "--encrypt", str(f.name)])
                cmd = nix_shell(["nixpkgs#sops"], args)
                subprocess.run(cmd, check=True)
                # atomic copy of the encrypted file
                with NamedTemporaryFile(dir=folder, delete=False) as f2:
                    shutil.copyfile(f.name, f2.name)
                    os.rename(f2.name, secret_path)
            finally:
                try:
                    os.remove(f.name)
                except OSError:
                    pass

def encrypt_secret(
    flake_dir: Path,
    secret: Path,
    value: IO[str] | str | None,
    add_users: list[str] = [],
    add_machines: list[str] = [],
    add_groups: list[str] = [],
) -> None:
    key = ensure_sops_key(flake_dir)
    keys = set([])

    for user in add_users:
        allow_member(
            users_folder(flake_dir, secret.name),
            sops_users_folder(flake_dir),
            user,
            False,
        )

    for machine in add_machines:
        allow_member(
            machines_folder(flake_dir, secret.name),
            sops_machines_folder(flake_dir),
            machine,
            False,
        )

    for group in add_groups:
        allow_member(
            groups_folder(flake_dir, secret.name),
            sops_groups_folder(flake_dir),
            group,
            False,
        )

    keys = collect_keys_for_path(secret)

    if key.pubkey not in keys:
        keys.add(key.pubkey)
        allow_member(
            users_folder(flake_dir, secret.name),
            sops_users_folder(flake_dir),
            key.username,
            False,
        )

    encrypt_file(secret / "secret", value, list(sorted(keys)))

def generate_private_key() -> tuple[str, str]:
    cmd = "age-keygen"
    try:
        proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
        res = proc.stdout.strip()
        pubkey = None
        private_key = None
        for line in res.splitlines():
            if line.startswith("# public key:"):
                pubkey = line.split(":")[1].strip()
            if not line.startswith("#"):
                private_key = line
        if not pubkey:
            raise ClanError("Could not find public key in age-keygen output")
        if not private_key:
            raise ClanError("Could not find private key in age-keygen output")
        return private_key, pubkey
    except subprocess.CalledProcessError as e:
        raise ClanError("Failed to generate private sops key") from e

def generate_host_key(flake_dir: Path, machine_name: str) -> None:
    if has_machine(flake_dir, machine_name):
        return
    priv_key, pub_key = generate_private_key()
    encrypt_secret(
       flake_dir,
       sops_secrets_folder(flake_dir) / f"{machine_name}-age.key",
       priv_key,
    )
    add_machine(flake_dir, machine_name, pub_key, False)

def generate_secrets_group(
    flake_dir: Path,
    secret_group: str,
    machine_name: str,
    tempdir: Path,
    secret_options: dict[str, Any],
) -> None:
    clan_dir = flake_dir
    secrets = secret_options["secrets"]
    needs_regeneration = any(
        not has_secret(flake_dir, f"{machine_name}-{name}") for name in secrets
    ) or any(
        not (flake_dir / fact).exists() for fact in secret_options["facts"].values()
    )

    generator = secret_options["generator"]
    subdir = tempdir / secret_group
    if needs_regeneration:
        facts_dir = subdir / "facts"
        facts_dir.mkdir(parents=True)
        secrets_dir = subdir / "secrets"
        secrets_dir.mkdir(parents=True)

        text = f"""
set -euo pipefail
export facts={shlex.quote(str(facts_dir))}
export secrets={shlex.quote(str(secrets_dir))}
{generator}
        """
        try:
            cmd = [text]
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError:
            msg = "failed to the following command:\n"
            msg += text
            raise ClanError(msg)
        for name in secrets:
            secret_file = secrets_dir / name
            if not secret_file.is_file():
                msg = f"did not generate a file for '{name}' when running the following command:\n"
                msg += text
                raise ClanError(msg)
            encrypt_secret(
                flake_dir,
                sops_secrets_folder(flake_dir) / f"{machine_name}-{name}",
                secret_file.read_text(),
                add_machines=[machine_name],
            )
        for name, fact_path in secret_options["facts"].items():
            fact_file = facts_dir / name
            if not fact_file.is_file():
                msg = f"did not generate a file for '{name}' when running the following command:\n"
                msg += text
                raise ClanError(msg)
            fact_path = clan_dir / fact_path
            fact_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fact_file, fact_path)


# this is called by the sops.nix clan core module
def generate_secrets_from_nix(
    machine_name: str,
    secret_submodules: dict[str, Any],
) -> None:
    flake_dir = Path(os.environ["REPO_DIR"])
    generate_host_key(flake_dir, machine_name)
    errors = {}
    log.debug("Generating secrets for machine %s and flake %s", machine_name, flake_dir)
    with TemporaryDirectory() as d:
        # if any of the secrets are missing, we regenerate all connected facts/secrets
        for secret_group, secret_options in secret_submodules.items():
            try:
                generate_secrets_group(
                    flake_dir, secret_group, machine_name, Path(d), secret_options
                )
            except ClanError as e:
                errors[secret_group] = e
    for secret_group, error in errors.items():
        print(f"failed to generate secrets for {machine_name}/{secret_group}:")
        print(error, file=sys.stderr)
    if len(errors) > 0:
        sys.exit(1)

def user_config_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.getenv("APPDATA", os.path.expanduser("~\\AppData\\Roaming\\")))
    elif sys.platform == "darwin":
        return Path(os.path.expanduser("~/Library/Application Support/"))
    else:
        return Path(os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config")))

def ensure_user_or_machine(flake_dir: Path, pub_key: str) -> SopsKey:
    key = SopsKey(pub_key, username="")
    folders = [sops_users_folder(flake_dir), sops_machines_folder(flake_dir)]
    for folder in folders:
        if folder.exists():
            for user in folder.iterdir():
                if not (user / "key.json").exists():
                    continue

                if read_key(user) == pub_key:
                    key.username = user.name
                    return key

    raise ClanError(
        f"Your sops key is not yet added to the repository. Please add it with 'clan secrets users add youruser {pub_key}' (replace youruser with your user name)"
    )

def setup_logging(level: Any) -> None:
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(CustomFormatter())
    logger = logging.getLogger("registerHandler")
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(level=logging.WARNING)
    logger.addHandler(handler)
    logging.basicConfig(level=level, handlers=[handler])

class CustomFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return FORMATTER[record.levelno](record, True).format(record)

grey = "\x1b[38;20m"
yellow = "\x1b[33;20m"
red = "\x1b[31;20m"
bold_red = "\x1b[31;1m"
green = "\u001b[32m"
blue = "\u001b[34m"

def get_formatter(color: str) -> Callable[[logging.LogRecord, bool], logging.Formatter]:
    def myformatter(
        record: logging.LogRecord, with_location: bool
    ) -> logging.Formatter:
        reset = "\x1b[0m"
        filepath = Path(record.pathname).resolve()
        if not with_location:
            return logging.Formatter(f"{color}%(levelname)s{reset}: %(message)s")

        return logging.Formatter(
            f"{color}%(levelname)s{reset}: %(message)s\n       {filepath}:%(lineno)d::%(funcName)s\n"
        )

    return myformatter

FORMATTER = {
    logging.DEBUG: get_formatter(blue),
    logging.INFO: get_formatter(green),
    logging.WARNING: get_formatter(yellow),
    logging.ERROR: get_formatter(red),
    logging.CRITICAL: get_formatter(bold_red),
}
    
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument( "--json", type=Path, required=True )
    parser.add_argument(
        "--debug",
        help="Enable debug logging",
        action="store_true",
    )
    args = parser.parse_args()
    
    if args.debug:
        setup_logging(logging.DEBUG)
        log.debug("Debug log activated")
    else:
        setup_logging(logging.INFO)
        
    with open(args.json) as f:
        data = json.load(f)

    generate_secrets_from_nix(**data)

if __name__ == "__main__":
    main()
