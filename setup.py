from setuptools import setup, find_packages

setup(
    name="certbot-dns-gigahost",
    version="0.1.2",
    description="Custom Certbot DNS Authenticator for MyDNSProvider",
    packages=find_packages(),
    install_requires=["certbot", "requests", "requests-mock", "bs4", "lxml", ],
    entry_points={
        "certbot.plugins": [
            "dns-gigahost = certbot_dns_gigahost.dns_gigahost:Authenticator",
        ],
    },
)
