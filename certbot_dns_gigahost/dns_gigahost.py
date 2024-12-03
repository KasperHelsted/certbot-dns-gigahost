"""DNS Authenticator for gigahost.dk"""

import base64
from contextlib import AbstractContextManager

import requests
from certbot.errors import PluginError
from certbot.plugins import dns_common


class Authenticator(dns_common.DNSAuthenticator):
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
            self._request("POST", f"/dns/_add_record", data)
        except requests.exceptions.RequestException as exp:
            raise PluginError(f"Error adding TXT record: {exp}") from exp

    def del_txt_record(self, domain, validation_name, validation):
        pass
        # """Delete a TXT record using the supplied information."""
        # product = self._find_product_id(domain)
        #
        # response = self._request("GET", f"/my/products/{product}/dns/records/")
        #
        # for record in response["records"]:
        #     if (
        #             record["type"] == "TXT"
        #             and record["name"] == validation_name
        #             and record["data"] == validation
        #     ):
        #         try:
        #             self._request(
        #                 "DELETE",
        #                 f"/my/products/{product}/dns/records/{record['record_id']}/",
        #             )
        #         except requests.exceptions.RequestException as exp:
        #             raise PluginError(f"Error deleting TXT record: {exp}") from exp

    # https://controlcenter.gigahost.dk/?module=dns&page=index&domain_name=homehq.dk
    def _find_product_id(self, domain: str):
        base_domain_guesses = dns_common.base_domain_name_guesses(domain)
        response = self._request("GET", "/my/products/")
        for product in response["products"]:
            if "domain" in product:
                if product["domain"]["name"] in base_domain_guesses:
                    return product["object"]
                if product["domain"]["name_idn"] in base_domain_guesses:
                    return product["object"]

        raise PluginError(
            f"No product is matching {base_domain_guesses} for domain {domain}"
        )

    @staticmethod
    def _split_domain(validation_name, domain):
        validation_name = validation_name.replace(f".{domain}", "")
        return validation_name, domain

    @staticmethod
    def _base64_encode(data):
        return base64.b64encode(data.encode()).decode()

    def _request(self, method, endpoint, data=None):
        url = f"{self.API_URL}{endpoint}"
        response = requests.request(
            method, url, headers=self.headers, files=data, timeout=30, allow_redirects=False
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
        response = self._request("POST", '/login/_login', data)

        self.session.cookies = response.cookies
