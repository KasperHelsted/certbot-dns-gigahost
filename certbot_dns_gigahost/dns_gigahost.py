"""DNS Authenticator for gigahost.dk"""
import base64
import logging
import re
from contextlib import AbstractContextManager

import requests
from bs4 import BeautifulSoup
from certbot.errors import PluginError
from certbot.plugins import dns_common
from certbot.plugins.dns_common import DNSAuthenticator

logger = logging.getLogger(__name__)


class Authenticator(DNSAuthenticator):
    """DNS Authenticator for gigahost.dk
    This Authenticator uses the gigahost.dk API to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record (DNS-01 challenge) with gigahost.dk"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=60):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=default_propagation_seconds
        )
        add("credentials", help="gigahost.dk API credentials INI file.")

    def more_info(self):
        return "This plugin configures a DNS TXT record to respond to a DNS-01 challenge using the gigahost.dk API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "gigahost.dk API credentials INI file",
            {
                "username": "Account name for gigahost.dk API",
                "password": "API key for gigahost.dk API",
            },
        )

    def _perform(self, domain, validation_name, validation):
        with self._get_gigahost_client() as client:
            client.add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        with self._get_gigahost_client() as client:
            client.del_txt_record(domain, validation_name, validation)

    def _get_gigahost_client(self):
        return GigahostClient(
            self.credentials.conf("username"),
            self.credentials.conf("password"),
        )


def get_product_name(domain):
    """Extract the product name from the domain."""
    parts = domain.split(".")
    if len(parts) < 2:
        return domain

    return ".".join(parts[-2:])


class GigahostClient(AbstractContextManager):
    """Encapsulates all communication with the gigahost.dk API."""

    API_URL = "https://controlcenter.gigahost.dk"
    RECORD_REGEX = re.compile(r'record=(\d+)')

    def __init__(self, username, password):
        self.username = username
        self.password = password

        self.headers = {
            'User-Agent': 'Mozilla/5.0'
        }

        self.session = requests.Session()
        self.authenticate(username, password)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.close()

    def add_txt_record(self, domain, validation_name, validation):
        """Add a TXT record using the supplied information."""
        # product = self._find_product_id(domain)

        data = {
            'domain_name': domain,
            'record_name': validation_name,
            "record_type": "TXT",
            "record_content": validation,
            "priority": 0,
            "record_ttl": 3600,
        }
        try:
            self._request("POST", f"/dns/_add_record", data=data)
        except requests.exceptions.RequestException as exp:
            raise PluginError(f"Error adding TXT record: {exp}") from exp

    def del_txt_record(self, domain, validation_name, validation):
        """Delete a TXT record using the supplied information."""
        product = self._find_product_id(domain, validation_name)

        data = {
            'domain_name': domain,
            'record': product
        }

        self._request('POST', '/dns/_delete_record', data=data)

    def _find_product_id(self, domain: str, validation_name: str) -> str:
        """
        Find the product ID for a given domain and validation name.

        Args:
            domain (str): The domain name to search for.
            validation_name (str): The validation name to match.

        Returns:
            str: The product ID if found.

        Raises:
            PluginError: If no matching product ID is found.
        """
        # Generate base domain guesses for error handling
        base_domain_guesses = dns_common.base_domain_name_guesses(domain)

        # Fetch DNS page content for the specified domain
        response = self._request('GET', f'/?module=dns&page=index&domain_name={domain}')
        soup = BeautifulSoup(response.text, 'lxml')

        # Locate the grandparent element containing the validation name
        validation_element = soup.find("small", string=validation_name)
        if validation_element is None:
            raise PluginError(
                f"No product matches {base_domain_guesses} for domain {domain}"
            )
        grandparent = validation_element.parent.parent

        # Find the "Delete" link associated with the validation name
        delete_link = grandparent.find("a", string='Slet')

        # Extract the product ID from the "href" attribute using regex
        match = self.RECORD_REGEX.search(delete_link['href'])
        if match:
            return match.group(1)

        # Handle cases where expected elements are not found
        raise PluginError(
            f"No product matches {base_domain_guesses} for domain {domain}"
        )

    @staticmethod
    def _split_domain(validation_name, domain):
        validation_name = validation_name.replace(f".{domain}", "")
        return validation_name, domain

    @staticmethod
    def _base64_encode(data):
        return base64.b64encode(data.encode()).decode()

    def _request(self, method, endpoint, url=None, data=None):
        url = f"{self.API_URL}{endpoint}" if url is None else url
        response = self.session.request(
            method, url, headers=self.headers, data=data, timeout=30
        )

        response.raise_for_status()

        return response

    def authenticate(self, username, password):
        data = {
            'username': username,
            'password': password,
            'redir_to': '',
            'language': 'da',
            'timezone_offset': '60'
        }
        response = self._request("POST", '/login/_login', data=data)
