import os
import unittest
from unittest import mock
from unittest.mock import patch, MagicMock

import requests_mock

from certbot_dns_gigahost.dns_gigahost import Authenticator, GigahostClient, PluginError


class TestAuthenticator(unittest.TestCase):
    @patch('certbot_dns_gigahost.dns_gigahost.GigahostClient')
    def setUp(self, MockGigahostClient):
        path = os.path.join('tests/', "fake_credentials.ini")

        self.config = mock.MagicMock(
            credentials=path
        )

        self.authenticator = Authenticator(config=self.config, name="gigahost")
        self.authenticator.credentials = MagicMock()
        self.authenticator.credentials.conf.side_effect = lambda key: {
            'username': 'test_user',
            'password': 'test_pass'
        }[key]
        self.mock_client = MockGigahostClient.return_value

    @patch.object(GigahostClient, 'add_txt_record')
    def test_perform_adds_txt_record(self, mock_add_txt_record):
        self.authenticator._perform('example.com', '_acme-challenge.example.com', 'test_value')
        mock_add_txt_record.assert_called_once_with('example.com', '_acme-challenge.example.com', 'test_value')

    @patch.object(GigahostClient, 'del_txt_record')
    def test_cleanup_deletes_txt_record(self, mock_del_txt_record):
        self.authenticator._cleanup('example.com', '_acme-challenge.example.com', 'test_value')
        mock_del_txt_record.assert_called_once_with('example.com', '_acme-challenge.example.com', 'test_value')


class TestGigahostClient(unittest.TestCase):
    def setUp(self):
        self.client = GigahostClient('test_user', 'test_pass')

    @requests_mock.Mocker()
    def test_authenticate(self, mocker):
        mocker.post('https://controlcenter.gigahost.dk/login/_login', status_code=200)
        self.client.authenticate('test_user', 'test_pass')

    @requests_mock.Mocker()
    def test_add_txt_record(self, mocker):
        mocker.post('https://controlcenter.gigahost.dk/dns/_add_record', status_code=200)
        self.client.add_txt_record('example.com', '_acme-challenge.example.com', 'test_value')

    @requests_mock.Mocker()
    def test_del_txt_record(self, mocker):
        mocker.post('https://controlcenter.gigahost.dk/dns/_delete_record', status_code=200)
        self.client._find_product_id = MagicMock(return_value='12345')
        self.client.del_txt_record('example.com', '_acme-challenge.example.com', 'test_value')

    @requests_mock.Mocker()
    def test_request_error_handling(self, mocker):
        mocker.post('https://controlcenter.gigahost.dk/dns/_add_record', status_code=500)
        with self.assertRaises(PluginError):
            self.client.add_txt_record('example.com', '_acme-challenge.example.com', 'test_value')


if __name__ == '__main__':
    unittest.main()
