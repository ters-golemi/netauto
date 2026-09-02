"""User accounts for the web GUI.

Accounts live in a YAML file holding bcrypt hashes, never plaintext. The file
is the source of truth and is re-read on each lookup, so adding or removing a
user takes effect without restarting the server.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bcrypt
import yaml

from netauto.errors import NetautoError

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
MIN_PASSWORD_LENGTH = 10
BCRYPT_ROUNDS = 12


class UserError(NetautoError):
    """Account management failed."""


@dataclass(frozen=True)
class User:
    name: str
    admin: bool = False


def default_path() -> Path:
    """Where accounts live: NETAUTO_USERS_FILE, else users.yaml beside the package."""
    env = os.environ.get("NETAUTO_USERS_FILE")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent / "users.yaml"


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters. "
            f"This account can read network device configuration."
        )
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


class UserStore:
    """Reads and writes the accounts file."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_path()

    # -- reading ---------------------------------------------------------

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        data = yaml.safe_load(self.path.read_text()) or {}
        users = data.get("users", {})
        if not isinstance(users, dict):
            raise UserError(f"{self.path}: 'users' must be a mapping of name to account.")
        return users

    def exists(self) -> bool:
        return self.path.exists()

    def list(self) -> list[User]:
        return [
            User(name=name, admin=bool(rec.get("admin", False)))
            for name, rec in sorted(self._read().items())
        ]

    def get(self, name: str) -> User | None:
        rec = self._read().get(name)
        if rec is None:
            return None
        return User(name=name, admin=bool(rec.get("admin", False)))

    def verify(self, name: str, password: str) -> User | None:
        """Return the user when the password matches, else None.

        A missing user still runs a bcrypt comparison against a dummy hash, so
        response time does not reveal whether the account exists.
        """
        rec = self._read().get(name)
        stored = rec.get("password_hash", "") if rec else ""
        if not stored:
            # Constant-ish work for unknown users.
            bcrypt.checkpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
            return None
        try:
            ok = bcrypt.checkpw(password.encode(), stored.encode())
        except (ValueError, TypeError) as exc:
            raise UserError(f"{name}: stored hash is not valid bcrypt: {exc}") from exc
        if not ok:
            return None
        return User(name=name, admin=bool(rec.get("admin", False)))

    # -- writing ---------------------------------------------------------

    def _write(self, users: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = yaml.safe_dump({"users": users}, sort_keys=True, default_flow_style=False)
        header = (
            "# Netauto web accounts. Passwords are bcrypt hashes, never plaintext.\n"
            "# Manage with: .venv/bin/python -m netauto.web.manage --help\n"
        )
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(header + payload)
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def add(self, name: str, password: str, *, admin: bool = False) -> User:
        if not USERNAME_RE.match(name):
            raise UserError(
                f"Invalid username {name!r}. Use 2-32 characters: lowercase letters, "
                f"digits, dot, underscore or hyphen, starting with a letter or digit."
            )
        users = self._read()
        if name in users:
            raise UserError(f"User {name!r} already exists. Use 'passwd' to change it.")
        users[name] = {"password_hash": hash_password(password), "admin": bool(admin)}
        self._write(users)
        return User(name=name, admin=admin)

    def set_password(self, name: str, password: str) -> None:
        users = self._read()
        if name not in users:
            raise UserError(f"No such user {name!r}.")
        users[name]["password_hash"] = hash_password(password)
        self._write(users)

    def remove(self, name: str) -> None:
        users = self._read()
        if name not in users:
            raise UserError(f"No such user {name!r}.")
        remaining_admins = [
            n for n, r in users.items() if r.get("admin") and n != name
        ]
        if users[name].get("admin") and not remaining_admins:
            raise UserError(
                f"{name!r} is the only admin. Promote another account first, or the "
                f"activity log becomes unreachable."
            )
        del users[name]
        self._write(users)

    def set_admin(self, name: str, admin: bool) -> None:
        users = self._read()
        if name not in users:
            raise UserError(f"No such user {name!r}.")
        users[name]["admin"] = bool(admin)
        self._write(users)
