"""Configuration owned only by the isolated KoS MINT co-signer."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class KosMintExecuteSignerSettings(BaseSettings):
    """Fail-closed settings for the dedicated testnet-only signer process.

    The coordinator has a separate settings model and never reads these
    values. In particular, the private key must be supplied by a protected
    systemd credential file, never an environment variable or release asset.
    """

    model_config = SettingsConfigDict(
        env_prefix="SOLSLOT_KOS_SIGNER_",
        env_file=None,
        extra="ignore",
    )

    private_key_file: str
    ledger_db_path: str = "./state/kos_mint_execute_signatures.db"
    public_artifact_path: str = "./state/public_artifact_v3.json"
    release_metadata_path: str = "./release.json"

    network: Literal["testnet11"] = "testnet11"
    coinset_base_url: str = "https://testnet11.api.coinset.org"
    coinset_timeout_seconds: float = Field(20.0, gt=0, le=30)

    bind_host: str = "127.0.0.1"
    bind_port: int = Field(9445, ge=1024, le=65535)
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    tls_client_ca_file: str | None = None

    @field_validator("coinset_base_url")
    @classmethod
    def _coinset_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("coinset_base_url must use HTTPS")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _private_listener(self) -> "KosMintExecuteSignerSettings":
        # A public listener would turn this deliberately narrow signer into a
        # remotely triggerable availability target. Deploy across WireGuard or
        # a local mTLS proxy, not on an Internet-facing interface.
        if self.bind_host not in {"127.0.0.1", "::1"} and not self.bind_host.startswith("10."):
            raise ValueError("bind_host must be loopback or a private 10/8 address")
        return self

    def require_mtls_listener(self) -> tuple[str, str, str]:
        values = (self.tls_cert_file, self.tls_key_file, self.tls_client_ca_file)
        if not all(values):
            raise RuntimeError(
                "KoS signer requires TLS certificate, private key, and client CA files."
            )
        return tuple(str(value) for value in values)


@lru_cache(maxsize=1)
def get_kos_mint_execute_signer_settings() -> KosMintExecuteSignerSettings:
    return KosMintExecuteSignerSettings()


__all__ = [
    "KosMintExecuteSignerSettings",
    "get_kos_mint_execute_signer_settings",
]
