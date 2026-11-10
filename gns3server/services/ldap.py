#
# Copyright (C) 2026 GNS3 Technologies Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
LDAP and Active Directory authentication service.

Provides directory authentication, user attribute retrieval, and group-to-RBAC
mapping using pure-Python ldap3. Blocking network I/O operations are run in a
worker thread pool to preserve FastAPI's async event loop.
"""

import asyncio
import logging
import os
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ldap3 import ALL, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from gns3server.config import Config
from gns3server.schemas.config import LDAPSettings

log = logging.getLogger(__name__)


@dataclass
class LDAPUserProfile:
    """
    Profile information retrieved from LDAP upon successful authentication.
    """

    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    groups: List[str] = field(default_factory=list)


def _extract_cn(dn_or_name: str) -> str:
    """
    Extract the Common Name (CN) from an LDAP Distinguished Name,
    or return the input unchanged if it is not a DN.
    """
    for part in dn_or_name.split(","):
        part = part.strip()
        if part.lower().startswith("cn="):
            return part[3:].strip()
    return dn_or_name.strip()


def _extract_entry_groups(user_entry: Any) -> Set[str]:
    """
    Extract raw group identifiers from memberOf/member user entry attributes.
    """
    groups: Set[str] = set()
    for attr_name in ("memberOf", "member"):
        if not hasattr(user_entry, attr_name):
            continue
        attr = getattr(user_entry, attr_name)
        values = getattr(attr, "values", None) or getattr(attr, "value", None)
        if isinstance(values, (list, tuple, set)):
            for val in values:
                groups.add(str(val))
        elif values:
            groups.add(str(values))
    return groups


def _search_directory_groups(conn: Connection, user_dn: str, clean_username: str, settings: LDAPSettings) -> Set[str]:
    """
    Search for group objects in the directory matching the user.
    """
    groups: Set[str] = set()
    search_base = settings.group_search_base or settings.base_dn
    if not (settings.group_search_filter and search_base):
        return groups

    clean_user_dn = escape_filter_chars(user_dn)
    grp_filter = settings.group_search_filter.format(user_dn=clean_user_dn, username=clean_username)
    try:
        conn.search(search_base=search_base, search_filter=grp_filter, attributes=["cn"])
        for entry in conn.entries:
            groups.add(entry.entry_dn)
            cn = getattr(entry, "cn", None)
            if cn and cn.value:
                groups.add(str(cn.value))
    except Exception as e:
        log.warning("LDAP group search query failed for %s: %s", clean_username, e)
    return groups


def _map_to_user_groups(raw_groups: Set[str], group_mapping: Dict[str, str], default_group: str) -> List[str]:
    """
    Map raw LDAP group names/DNs to configured GNS3 UserGroups.
    """
    mapped_groups: List[str] = []
    for raw_group in raw_groups:
        cn = _extract_cn(raw_group)
        target_group = None
        for map_key, map_val in group_mapping.items():
            if map_key.lower() in (raw_group.lower(), cn.lower()):
                target_group = map_val
                break
        if target_group and target_group not in mapped_groups:
            mapped_groups.append(target_group)

    if not mapped_groups and default_group:
        mapped_groups.append(default_group)
    return mapped_groups


class LDAPService:
    """
    Asynchronous LDAP/Active Directory service.
    """

    def __init__(self, server: Optional[Server] = None, client_strategy: str = "SYNC") -> None:
        self._server = server
        self._client_strategy = client_strategy

    def _create_server(self, settings: LDAPSettings) -> Server:
        use_ssl = settings.uri.startswith("ldaps://")
        tls_config = None

        if use_ssl or settings.start_tls:
            validate_cert = ssl.CERT_REQUIRED if settings.verify_cert else ssl.CERT_NONE
            ca_file = settings.ca_cert_file if settings.ca_cert_file and os.path.exists(settings.ca_cert_file) else None
            tls_config = Tls(validate=validate_cert, ca_certs_file=ca_file)

        return Server(
            settings.uri,
            use_ssl=use_ssl,
            tls=tls_config,
            connect_timeout=settings.timeout,
            get_info=ALL,
        )

    def _create_connection(
        self, server: Server, user: Optional[str], password: Optional[str], timeout: int
    ) -> Connection:
        return Connection(
            server,
            user=user,
            password=password,
            auto_bind=False,
            receive_timeout=timeout,
            client_strategy=self._client_strategy,
        )

    def _bind_connection(self, conn: Connection, start_tls: bool, uri: str) -> bool:
        if start_tls and not uri.startswith("ldaps://"):
            try:
                conn.open()
                conn.start_tls()
            except Exception as e:
                log.error("LDAP StartTLS negotiation failed: %s", e)
                return False
        return bool(conn.bind())

    def _resolve_groups(
        self,
        conn: Connection,
        user_entry: Any,
        user_dn: str,
        clean_username: str,
        settings: LDAPSettings,
    ) -> List[str]:
        raw_groups = _extract_entry_groups(user_entry)
        raw_groups |= _search_directory_groups(conn, user_dn, clean_username, settings)
        return _map_to_user_groups(raw_groups, settings.group_mapping or {}, settings.default_group)

    def _verify_user_credentials(self, server: Server, user_dn: str, password: str, settings: LDAPSettings) -> bool:
        user_conn = self._create_connection(server, user_dn, password, settings.timeout)
        try:
            return self._bind_connection(user_conn, settings.start_tls, settings.uri)
        except Exception as e:
            log.warning("LDAP user bind error for %s: %s", user_dn, e)
            return False
        finally:
            if user_conn.bound:
                user_conn.unbind()

    def _extract_profile(
        self,
        conn: Connection,
        user_entry: Any,
        username: str,
        user_dn: str,
        clean_username: str,
        settings: LDAPSettings,
    ) -> LDAPUserProfile:
        canonical_username = username
        user_attr = getattr(user_entry, settings.user_attr_username, None)
        if user_attr and user_attr.value:
            canonical_username = str(user_attr.value)

        email = None
        email_attr = getattr(user_entry, settings.user_attr_email, None)
        if email_attr and email_attr.value:
            email = str(email_attr.value)

        full_name = None
        fn_attr = getattr(user_entry, settings.user_attr_fullname, None)
        if fn_attr and fn_attr.value:
            full_name = str(fn_attr.value)

        groups = self._resolve_groups(conn, user_entry, user_dn, clean_username, settings)
        return LDAPUserProfile(
            username=canonical_username,
            email=email,
            full_name=full_name,
            groups=groups,
        )

    def _sync_authenticate(self, username: str, password: str, settings: LDAPSettings) -> Optional[LDAPUserProfile]:
        if not username or not password:
            return None

        clean_username = escape_filter_chars(username)
        server = self._server or self._create_server(settings)

        bind_user = settings.bind_dn
        bind_password = settings.bind_password.get_secret_value() if settings.bind_password else None

        conn = self._create_connection(server, bind_user, bind_password, settings.timeout)
        try:
            if not self._bind_connection(conn, settings.start_tls, settings.uri):
                log.warning("LDAP service account bind failed: %s", conn.result)
                return None

            search_filter = settings.user_search_filter.format(username=clean_username)
            attributes = [
                settings.user_attr_username,
                settings.user_attr_email,
                settings.user_attr_fullname,
                "memberOf",
                "member",
            ]
            conn.search(search_base=settings.base_dn, search_filter=search_filter, attributes=attributes, size_limit=1)

            if not conn.entries:
                log.info("LDAP user '%s' not found with filter: %s", clean_username, search_filter)
                return None

            user_entry = conn.entries[0]
            user_dn = user_entry.entry_dn

            if not self._verify_user_credentials(server, user_dn, password, settings):
                log.info("LDAP credential verification failed for user DN: %s", user_dn)
                return None

            return self._extract_profile(conn, user_entry, username, user_dn, clean_username, settings)

        except LDAPException as e:
            log.warning("LDAP protocol error during authentication: %s", e)
            return None
        except Exception as e:
            log.warning("Unexpected error during LDAP authentication for %s: %s", clean_username, e)
            return None
        finally:
            if conn.bound:
                conn.unbind()

    async def authenticate(
        self, username: str, password: str, settings: Optional[LDAPSettings] = None
    ) -> Optional[LDAPUserProfile]:
        """
        Authenticate against LDAP/Active Directory in a worker thread.
        """
        if settings is None:
            settings = Config.instance().settings.LDAP

        if not settings.enabled:
            return None

        if not username or not password:
            return None

        return await asyncio.to_thread(self._sync_authenticate, username, password, settings)
