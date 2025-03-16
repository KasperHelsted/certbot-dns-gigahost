from setuptools import setup, find_packages

setup(
    name="certbot-dns-gigahostdk",
    version="0.0.1",
    description="Custom Certbot DNS Authenticator for Gigahost.dk",
    packages=find_packages(),
    install_requires=["certbot", "requests", "requests-mock", "bs4", "lxml"],
    entry_points={
        "certbot.plugins": [
            "dns-gigahost = certbot_dns_gigahost.dns_gigahost:Authenticator",
        ],
    },
)
