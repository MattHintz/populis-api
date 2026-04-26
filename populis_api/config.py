"""Runtime configuration for the Populis API.

Values are loaded from environment variables (optionally via .env) by
pydantic-settings.  Secrets — the faucet key and the challenge secret —
are the two values that MUST be set in production.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Populis API runtime settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="POPULIS_",
        extra="ignore",
    )

    # ── Network ───────────────────────────────────────────────────────────
    network: Literal["testnet11", "mainnet"] = "testnet11"
    coinset_base_url: str = "https://testnet11.api.coinset.org"

    # ── Auth / challenges ────────────────────────────────────────────────
    challenge_ttl_seconds: int = 300
    # 32-byte hex string.  If empty a random one is generated per-process.
    challenge_secret: str = ""

    # ── Faucet (launcher payer) ──────────────────────────────────────────
    # ONE of these three must be set; without any the backend refuses to
    # register new vaults.
    #   * faucet_mnemonic           — 12/24-word BIP-39 mnemonic
    #   * faucet_seed_hex           — 32-byte hex entropy for AugSchemeMPL.key_gen
    #   * faucet_master_sk_hex      — 32-byte hex of a serialised BLS master PrivateKey
    #                                 (e.g. pulled directly out of Chia's keychain)
    faucet_mnemonic: Optional[str] = None
    faucet_seed_hex: Optional[str] = None
    faucet_master_sk_hex: Optional[str] = None
    # Maximum amount (mojos) a single faucet-funded launcher may consume.
    # Launchers themselves cost 1 mojo; the rest is fee headroom.
    faucet_max_spend_mojos: int = 10_000_000  # 0.01 XCH per registration

    # ── Protocol deployment ───────────────────────────────────────────────
    # Once the pool singleton, governance singleton and DID are launched on
    # testnet they are pinned here.  Vaults must reference the same pool.
    pool_launcher_id: Optional[str] = None
    governance_launcher_id: Optional[str] = None
    # Path to the persisted deployment manifest (JSON).  When set and present,
    # the API loads the plan on startup so it can serve /admin/deployment and
    # the protocol-aware vault flows without re-deploying.
    deployment_manifest_path: str = "./deployment_manifest.json"

    # ── Admin auth ────────────────────────────────────────────────────────
    # Bearer token required by all /admin/* endpoints.  When unset, /admin/*
    # endpoints are disabled (return 503) — the safest default for a public
    # endpoint without an explicit operator opt-in.  Generate with
    # `openssl rand -hex 32`.
    admin_token: Optional[str] = None

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins: str = "http://localhost:4200,http://localhost:5173"

    # ── EIP-712 domain ────────────────────────────────────────────────────
    eip712_name: str = "Populis Protocol"
    # v2 = post POP-CANON-002 audit fix (envelope now binds pool, auth_type,
    # network).  v1 signatures are intentionally NOT accepted.
    eip712_version: str = "2"
    # MUST match EIP712_DOMAIN_CHAIN_ID in populis_puzzles/vault_driver.py.
    eip712_chain_id: int = 1

    # ── DoS hardening (POP-CANON-003 / Strategy 7) ────────────────────────
    # Maximum number of pending challenges in memory at any time.  When the
    # cap is reached, /auth/challenge returns 429 to back off load.
    challenge_store_max_pending: int = 50_000
    # Maximum challenges issued per source IP per minute.
    challenge_per_ip_per_minute: int = 60

    # ── Faucet UTXO consolidation worker (POP-CANON-008) ──────────────────
    # Background task that periodically merges fragmented faucet change UTXOs
    # back into a single coin.  Disabled by default — operators must opt in
    # after verifying behaviour against their own faucet.
    faucet_consolidation_enabled: bool = False
    # When the unspent UTXO count exceeds this, the worker triggers a merge.
    faucet_consolidation_threshold: int = 50
    # Polling interval in seconds (default 10 min).
    faucet_consolidation_interval_seconds: float = 600.0
    # Fee paid by the consolidating spend bundle (mojos).  Default 0 — testnet
    # mempools accept zero-fee bundles when block space is available.
    faucet_consolidation_fee: int = 0
    # Cap on inputs per consolidation run (well below MAX_SPENDS_PER_BLOCK).
    faucet_consolidation_max_inputs: int = 500

    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
