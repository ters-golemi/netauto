"""Account store: hashing, validation, and the guards around removal."""

import pytest
import yaml

from netauto.web.users import UserError, UserStore


@pytest.fixture
def store(tmp_path):
    return UserStore(tmp_path / "users.yaml")


def test_add_and_verify(store):
    store.add("alice", "a-long-enough-password", admin=True)
    user = store.verify("alice", "a-long-enough-password")
    assert user and user.name == "alice" and user.admin


def test_wrong_password_returns_none(store):
    store.add("alice", "a-long-enough-password")
    assert store.verify("alice", "wrong-password-here") is None


def test_unknown_user_returns_none(store):
    store.add("alice", "a-long-enough-password")
    assert store.verify("mallory", "a-long-enough-password") is None


def test_password_is_never_stored_in_plaintext(store):
    secret = "a-long-enough-password"
    store.add("alice", secret)
    raw = store.path.read_text()
    assert secret not in raw
    assert yaml.safe_load(raw)["users"]["alice"]["password_hash"].startswith("$2b$")


def test_accounts_file_is_owner_only(store):
    store.add("alice", "a-long-enough-password")
    assert oct(store.path.stat().st_mode)[-3:] == "600"


def test_short_passwords_are_refused(store):
    with pytest.raises(UserError, match="at least"):
        store.add("alice", "short")


@pytest.mark.parametrize("name", ["", "A", "-bad", "has space", "x" * 40, "üser"])
def test_invalid_usernames_are_refused(store, name):
    with pytest.raises(UserError):
        store.add(name, "a-long-enough-password")


def test_duplicate_user_is_refused(store):
    store.add("alice", "a-long-enough-password")
    with pytest.raises(UserError, match="already exists"):
        store.add("alice", "another-long-password")


def test_password_change(store):
    store.add("alice", "a-long-enough-password")
    store.set_password("alice", "a-different-password")
    assert store.verify("alice", "a-long-enough-password") is None
    assert store.verify("alice", "a-different-password")


def test_cannot_remove_the_last_admin(store):
    store.add("alice", "a-long-enough-password", admin=True)
    store.add("bob", "a-long-enough-password")
    with pytest.raises(UserError, match="only admin"):
        store.remove("alice")
    store.remove("bob")          # non-admin removes fine


def test_can_remove_admin_when_another_exists(store):
    store.add("alice", "a-long-enough-password", admin=True)
    store.add("carol", "a-long-enough-password", admin=True)
    store.remove("alice")
    assert [u.name for u in store.list()] == ["carol"]


def test_changes_are_visible_without_reload(store):
    store.add("alice", "a-long-enough-password")
    assert store.verify("alice", "a-long-enough-password")
    store.remove("alice")
    assert store.verify("alice", "a-long-enough-password") is None
