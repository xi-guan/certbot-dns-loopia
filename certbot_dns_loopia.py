"""
Contains the Loopia DNS ACME authenticator class.
"""
import logging
import xmlrpc.client
from time import sleep
from typing import Any, Callable, Dict, Optional, Tuple
from xml.parsers.expat import ExpatError

import requests
from tldextract import TLDExtract
from certbot.errors import PluginError
from certbot.plugins.dns_common import DNSAuthenticator, CredentialsConfiguration
from certbot.configuration import NamespaceConfig

logger = logging.getLogger(__name__)


class LoopiaClient:  # pylint: disable=too-few-public-methods
    """
    Minimal client for the Loopia XML-RPC API, see https://www.loopia.com/api/
    """

    url = "https://api.loopia.se/RPCSERV"

    #: Seconds before a stalled API call is given up
    timeout = 30

    #: Tries per API call on connection errors, timeouts and HTTP 5xx
    attempts = 3

    def __init__(self, user: str, password: str) -> None:
        self._user = user
        self._password = password

    def call(self, method: str, *args: Any) -> Any:
        """
        Call an API method and return its result, raise PluginError on failure.
        """
        body = xmlrpc.client.dumps((self._user, self._password) + args, method)
        attempt = 1
        while True:
            try:
                response = requests.post(
                    self.url,
                    data=body.encode("utf-8"),
                    headers={"Content-Type": "text/xml"},
                    timeout=self.timeout,
                )
                if response.status_code < 500:
                    break
                error = f"HTTP {response.status_code}"
            except (requests.ConnectionError, requests.Timeout) as exc:
                error = str(exc)

            # a retried addZoneRecord may leave a duplicate, _cleanup removes all matches
            if attempt >= self.attempts:
                raise PluginError(f"Loopia API call {method} failed: {error}")
            logger.warning("Loopia API call %s failed (%s), retrying", method, error)
            sleep(2 * attempt)
            attempt += 1

        try:
            response.raise_for_status()
            result = xmlrpc.client.loads(response.content)[0][0]
        except (requests.HTTPError, xmlrpc.client.Error, ExpatError) as exc:
            raise PluginError(f"Loopia API call {method} failed: {exc}") from exc

        # loopia reports errors as a status string, alone or in a one-item list
        status = result[0] if isinstance(result, list) and len(result) == 1 else result
        if isinstance(status, str) and status != "OK":
            raise PluginError(f"Loopia API call {method} failed: {status}")
        return result


class LoopiaAuthenticator(DNSAuthenticator):
    """
    Loopia DNS ACME authenticator.

    This Authenticator uses the Loopia API to fulfill a dns-01 challenge.
    """

    #: Short description of plugin
    description = __doc__.strip().split("\n", 1)[0]

    #: TTL for the validation TXT record
    ttl = 30

    def __init__(self, config: NamespaceConfig, name: str) -> None:
        super().__init__(config, name)
        self._client = None
        self.credentials: Optional[CredentialsConfiguration] = None

        # Use empty tuple for param to prevent tldextract from performing live
        # HTTP request to update the TLD list
        self._tld_extract = TLDExtract(suffix_list_urls=())

    @classmethod
    def add_parser_arguments(
            cls,
            add: Callable[..., None],
            default_propagation_seconds: int = 15 * 60,
    ) -> None:
        super(LoopiaAuthenticator, cls).add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Loopia API credentials INI file.")

    def more_info(self) -> str:
        """
        More in-depth description of the plugin.
        """

        return "\n".join(line[4:] for line in __doc__.strip().split("\n"))

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "Loopia credentials INI file",
            {
                "user": "API username for Loopia account",
                "password": "API password for Loopia account",
            },
        )

    def _get_loopia_client(self) -> LoopiaClient:
        assert self.credentials, "Credentials not set"
        user = self.credentials.conf("user")
        password = self.credentials.conf("password")
        assert user and password, "Credentials not set"

        return LoopiaClient(user, password)

    def _split_domain(self, validation_name: str) -> Tuple[str, str]:
        """
        Split a name into the domain registered at Loopia and the subdomain.
        """
        parts = self._tld_extract(validation_name)
        return f"{parts.domain}.{parts.suffix}", parts.subdomain or "@"

    def _txt_record(self, validation: str) -> Dict[str, Any]:
        return {"type": "TXT", "ttl": self.ttl, "priority": 0, "rdata": validation}

    def _perform(
        self,
        domain: str,
        validation_name: str,
        validation: str,
    ) -> None:
        loopia = self._get_loopia_client()
        loopia_domain, subdomain = self._split_domain(validation_name)

        msg = "Creating TXT record for %s on subdomain %s"
        logger.debug(msg, loopia_domain, subdomain)

        loopia.call(
            "addZoneRecord",
            loopia_domain,
            subdomain,
            dict(self._txt_record(validation), record_id=0),
        )

    def _cleanup(
        self,
        domain: str,
        validation_name: str,
        validation: str,
    ) -> None:
        loopia = self._get_loopia_client()
        loopia_domain, subdomain = self._split_domain(validation_name)
        dns_record = self._txt_record(validation)

        records = loopia.call("getZoneRecords", loopia_domain, subdomain)

        delete_subdomain = True
        for record in records:
            # Make sure the record we delete actually matches the created
            if all(record.get(key) == value for key, value in dns_record.items()):
                logger.debug("Removing zone record %s", record)
                loopia.call(
                    "removeZoneRecord",
                    loopia_domain,
                    subdomain,
                    record["record_id"],
                )
            else:
                # This happens if there are other zone records on the current
                # sub domain.
                delete_subdomain = False

                msg = "Record {} prevents the subdomain from being deleted"
                logger.debug(msg, record)

        # Delete subdomain if we emptied it completely
        if delete_subdomain:
            msg = "Removing subdomain %s on domain %s"
            logger.debug(msg, subdomain, loopia_domain)
            loopia.call("removeSubdomain", loopia_domain, subdomain)
