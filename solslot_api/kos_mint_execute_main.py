"""Entrypoint that starts the KoS signer with mandatory mutual TLS."""

from __future__ import annotations

import ssl

import uvicorn

from .kos_mint_execute_app import create_kos_mint_execute_app
from .kos_mint_execute_settings import get_kos_mint_execute_signer_settings


def main() -> None:
    settings = get_kos_mint_execute_signer_settings()
    cert_file, key_file, client_ca_file = settings.require_mtls_listener()
    uvicorn.run(
        create_kos_mint_execute_app(settings=settings),
        host=settings.bind_host,
        port=settings.bind_port,
        proxy_headers=False,
        forwarded_allow_ips="",
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
        ssl_ca_certs=client_ca_file,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


if __name__ == "__main__":
    main()
