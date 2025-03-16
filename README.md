# certbot-dns-gigahostdk

gigahost.dk DNS Authenticator plugin for Certbot.

## Installation

```sh
pip install certbot-dns-gigahostdk
```

## Usage

To start using DNS authentication for the gigahost.dk DNS API, pass the following arguments on certbot's command line:

| Option                         | Description                                          |
|--------------------------------|------------------------------------------------------|
| `--authenticator dns-gigahost` | select the authenticator plugin (Required)           |
| `--dns-gigahost-credentials`   | gigahost.dk DNS API credentials INI file. (Required) |

## Credentials

Username is the gigahost.dk account-number (Sxxxxxx) and the password is the API-KEY for the specific account.
The API-Key assigned to your gigahost.dk account can be found in your gigahost.dk Controlpanel.
Please make sure to use the absolute path - some users experienced problems with relative paths.

An example `credentials.ini` file:

```ini
dns_gigahost_account_name = Sxxxxxx
dns_gigahost_api_key = DSHJdsjh2812872sahj
```

## Examples

To acquire a certificate for `example.com`

```bash
certbot certonly \
 --authenticator dns-gigahost \
 --dns-gigahost-credentials /path/to/my/credentials.ini \
 -d example.com
```

To acquire a certificate for ``*.example.com``

```bash
   certbot certonly \
     --authenticator dns-gigahost \
     --dns-gigahost-credentials /path/to/my/credentials.ini \
     -d '*.example.com'
```
