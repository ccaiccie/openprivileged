"""Read-only Active Directory adapter. Connections are opened only on explicit use."""

import importlib
import os
import ssl
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from vg_core.domain import Role


class DirectoryDenied(Exception):
    """Invalid credentials, missing user, or disallowed account."""


class DirectoryUnavailable(Exception):
    """Directory could not be verified; callers must fail closed."""


class GroupMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    group_dn: str = Field(min_length=1)
    roles: tuple[Role, ...] = ()
    device_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DirectoryUser:
    id: str
    username: str
    display_name: str
    email: str
    groups: tuple[str, ...]


class DirectoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
    port: int = Field(default=636, ge=1, le=65535)
    ca_file: str = Field(min_length=1)
    bind_dn: str = Field(min_length=1)
    bind_password_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    user_base_dn: str = Field(min_length=1)
    group_base_dn: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    tenant_ids: frozenset[str] = Field(min_length=1)
    group_mappings: tuple[GroupMapping, ...] = Field(min_length=1)
    nested_groups: bool = False
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    max_users: int = Field(default=1000, ge=1, le=10000)

    @model_validator(mode="after")
    def validate_mappings(self) -> "DirectoryConfig":
        dns = [m.group_dn.casefold() for m in self.group_mappings]
        if len(dns) != len(set(dns)):
            raise ValueError("Duplicate directory group mapping")
        return self

    def roles_for(self, user: DirectoryUser) -> tuple[Role, ...]:
        groups = {g.casefold() for g in user.groups}
        return tuple(
            dict.fromkeys(
                r for m in self.group_mappings if m.group_dn.casefold() in groups for r in m.roles
            )
        )

    def devices_for(self, user: DirectoryUser) -> frozenset[str]:
        groups = {g.casefold() for g in user.groups}
        return frozenset(
            d for m in self.group_mappings if m.group_dn.casefold() in groups for d in m.device_ids
        )


class DirectoryProvider(Protocol):
    def authenticate(self, username: str, password: str) -> DirectoryUser: ...
    def lookup(self, user_id: str) -> DirectoryUser: ...
    def list_users(self) -> list[DirectoryUser]: ...
    def list_groups(self) -> list[dict[str, str]]: ...


def escape_filter(value: str) -> str:
    """RFC4515 escaping, including NUL, without interpolating raw LDAP filters."""
    return "".join(
        {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}.get(c, c)
        for c in value
    )


class LdapsDirectory:
    attributes = [
        "objectGUID",
        "sAMAccountName",
        "displayName",
        "mail",
        "memberOf",
        "userAccountControl",
        "accountExpires",
        "lockoutTime",
        "msDS-User-Account-Control-Computed",
    ]

    def __init__(self, config: DirectoryConfig, *, bind_password: str | None = None):
        self.config = config
        self._bind_password = bind_password

    @contextmanager
    def _connection(self, dn: str, password: str) -> Iterator[Any]:
        if not password:
            raise DirectoryDenied("Empty credentials are not permitted")
        connection = None
        try:
            ldap = importlib.import_module("ldap3")
            tls = ldap.Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ca_certs_file=self.config.ca_file,
                valid_names=[self.config.host],
            )
            server = ldap.Server(
                self.config.host,
                port=self.config.port,
                use_ssl=True,
                tls=tls,
                connect_timeout=self.config.timeout_seconds,
                get_info=ldap.NONE,
            )
            connection = ldap.Connection(
                server,
                user=dn,
                password=password,
                authentication=ldap.SIMPLE,
                auto_referrals=False,
                receive_timeout=self.config.timeout_seconds,
                raise_exceptions=False,
            )
            if not connection.bind():
                if connection.result.get("result") == 49:
                    raise DirectoryDenied("Directory authentication failed")
                raise DirectoryUnavailable("Directory bind failed")
            yield connection
        except (DirectoryDenied, DirectoryUnavailable):
            raise
        except Exception:
            # LDAP exceptions can contain credentials or server details: never relay them.
            raise DirectoryUnavailable("Directory connection or verification failed") from None
        finally:
            if connection is not None:
                with suppress(Exception):
                    connection.unbind()

    @contextmanager
    def _reader(self) -> Iterator[Any]:
        password = (
            self._bind_password
            if self._bind_password is not None
            else os.environ.get(self.config.bind_password_env, "")
        )
        if not password:
            raise DirectoryUnavailable("Directory reader credential is not configured")
        with ExitStack() as stack:
            try:
                connection = stack.enter_context(self._connection(self.config.bind_dn, password))
            except DirectoryDenied:
                raise DirectoryUnavailable("Directory reader authentication failed") from None
            yield connection

    def _search(
        self, connection: Any, base: str, query: str, attributes: list[str], limit: int
    ) -> list[dict[str, Any]]:
        connection.search(
            base,
            query,
            search_scope="SUBTREE",
            attributes=attributes,
            size_limit=limit,
            time_limit=self.config.timeout_seconds,
        )
        # Never authorize from partial, referral, size-limit or timeout responses.
        if connection.result.get("result") != 0:
            raise DirectoryUnavailable("Directory search incomplete")
        entries = [e for e in connection.response if e.get("type") == "searchResEntry"]
        if any(e.get("type") == "searchResRef" for e in connection.response):
            raise DirectoryUnavailable("Directory referrals are not accepted")
        return entries

    def _record(self, connection: Any, entry: dict[str, Any]) -> DirectoryUser:
        attrs = dict(entry["attributes"])
        # With get_info=NONE ldap3 has no schema and returns single-valued fields as lists.
        for name in self.attributes:
            value = attrs.get(name)
            if name != "memberOf" and isinstance(value, (list, tuple)):
                if len(value) > 1:
                    raise DirectoryDenied("Ambiguous directory attribute")
                attrs[name] = value[0] if value else None
        raw = entry.get("raw_attributes", {}).get("objectGUID")
        if raw:
            attrs["objectGUID"] = raw[0]

        # Missing account status is not evidence that an account is enabled.
        if attrs.get("userAccountControl") is None:
            raise DirectoryDenied("Directory account status missing")
        flags = int(attrs["userAccountControl"])
        computed = attrs.get("msDS-User-Account-Control-Computed")
        locked = (
            (int(computed) & 16) if computed is not None else int(attrs.get("lockoutTime") or 0)
        )
        if flags & 2 or flags & 16 or locked:
            raise DirectoryDenied("Directory account disabled or locked")
        expires = attrs.get("accountExpires")
        if isinstance(expires, datetime):
            if expires.year < 9999 and expires <= datetime.now(UTC):
                raise DirectoryDenied("Directory account expired")
        elif expires not in (None, [], 0, "0", 9223372036854775807, "9223372036854775807"):
            seconds = (int(expires) - 116444736000000000) / 10000000
            if seconds <= datetime.now(UTC).timestamp():
                raise DirectoryDenied("Directory account expired")
        raw_guid = attrs.get("objectGUID")
        if isinstance(raw_guid, bytes):
            guid = str(UUID(bytes_le=raw_guid))
        else:
            guid = str(UUID(str(raw_guid).strip("{}")))
        groups = tuple(attrs.get("memberOf") or ())
        if self.config.nested_groups:
            query = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="
            query += escape_filter(entry["dn"]) + "))"
            entries = self._search(
                connection, self.config.group_base_dn, query, ["distinguishedName"], 1000
            )
            groups = tuple(e["dn"] for e in entries)
        return DirectoryUser(
            guid,
            str(attrs["sAMAccountName"]),
            str(attrs.get("displayName") or ""),
            str(attrs.get("mail") or ""),
            groups,
        )

    def authenticate(self, username: str, password: str) -> DirectoryUser:
        if not username or not password or len(username) > 256 or len(password) > 1024:
            raise DirectoryDenied("Invalid directory credentials")
        with self._reader() as reader:
            query = "(&(objectCategory=person)(objectClass=user)(sAMAccountName="
            query += escape_filter(username) + "))"
            entries = self._search(reader, self.config.user_base_dn, query, self.attributes, 2)
            if len(entries) != 1:
                raise DirectoryDenied("Directory authentication failed")
            record = self._record(reader, entries[0])
            with self._connection(entries[0]["dn"], password):
                pass
            return record

    def lookup(self, user_id: str) -> DirectoryUser:
        try:
            guid_filter = "".join(f"\\{b:02x}" for b in UUID(user_id).bytes_le)
        except ValueError:
            raise DirectoryDenied("Invalid directory identity") from None
        with self._reader() as reader:
            query = f"(&(objectCategory=person)(objectClass=user)(objectGUID={guid_filter}))"
            entries = self._search(reader, self.config.user_base_dn, query, self.attributes, 2)
            if len(entries) != 1:
                raise DirectoryDenied("Directory user unavailable")
            return self._record(reader, entries[0])

    def list_groups(self) -> list[dict[str, str]]:
        """Discover security groups with bounded RFC2696 paging; never return partial results."""
        groups: dict[str, dict[str, str]] = {}
        with self._reader() as reader:
            cookie: bytes | str | None = None
            seen: set[bytes | str] = set()
            pages = 0
            while True:
                pages += 1
                if pages > 100:
                    raise DirectoryUnavailable("Directory group paging limit exceeded")
                reader.search(
                    self.config.group_base_dn,
                    "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))",
                    search_scope="SUBTREE",
                    attributes=["cn", "sAMAccountName"],
                    paged_size=500,
                    paged_criticality=True,
                    paged_cookie=cookie,
                    time_limit=self.config.timeout_seconds,
                )
                if reader.result.get("result") != 0 or any(
                    e.get("type") == "searchResRef" for e in reader.response
                ):
                    raise DirectoryUnavailable("Directory group search incomplete")
                for entry in reader.response:
                    if entry.get("type") != "searchResEntry":
                        continue
                    dn = str(entry["dn"])
                    name = entry.get("attributes", {}).get("cn") or dn
                    if isinstance(name, (list, tuple)):
                        name = name[0] if name else dn
                    groups[dn.casefold()] = {"dn": dn, "name": str(name)}
                if len(groups) > 10000:
                    raise DirectoryUnavailable(
                        "Narrow the group search base (maximum 10000 groups)"
                    )
                control = reader.result.get("controls", {}).get("1.2.840.113556.1.4.319")
                if not isinstance(control, dict) or not isinstance(control.get("value"), dict):
                    raise DirectoryUnavailable("Directory did not confirm paged results")
                cookie = control["value"].get("cookie")
                if not isinstance(cookie, (bytes, str)):
                    raise DirectoryUnavailable("Directory returned an invalid page cookie")
                if not cookie:
                    break
                if cookie in seen:
                    raise DirectoryUnavailable("Directory group paging did not advance")
                seen.add(cookie)
        return sorted(groups.values(), key=lambda g: (g["name"].casefold(), g["dn"].casefold()))

    def list_users(self) -> list[DirectoryUser]:
        with self._reader() as reader:
            entries = self._search(
                reader,
                self.config.user_base_dn,
                "(&(objectCategory=person)(objectClass=user))",
                self.attributes,
                self.config.max_users,
            )
            result = []
            for entry in entries:
                try:
                    record = self._record(reader, entry)
                except DirectoryDenied:
                    continue
                if self.config.roles_for(record):
                    result.append(record)
            return result
