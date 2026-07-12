"""Short-lived challenge store for wallet login.

The backend issues a 32-byte random nonce + an EIP-712 typed data envelope.
The caller (frontend) signs the typed data with the user's wallet and sends
back (address, nonce, signature).  We re-derive the digest, ecrecover the
pubkey, and if (a) the address matches and (b) the nonce is still alive,
we accept it.

Nonces are single-use: we pop them on successful verification.  TTL is
enforced in-memory per process (good enough for a single-server MVP — swap
for Redis later).

Audit history:

- POP-CANON-006 / LD-1 (CANON_SOLSLOT_API_AUDIT_2026_04_26):
  ``pop()`` previously left the challenge entry in the store on validation
  failure (wrong address / wrong auth_type).  Now ALL pop attempts remove
  the entry — strict write-once-read-once.  This prevents an attacker from
  using validation failures to keep the store full.

- POP-CANON-003 / Strategy 7: ``issue()`` now respects ``max_pending`` and
  per-IP rate limits to bound memory growth under DoS.

- POP-CANON-002 / SIGCOV-1: ``Challenge`` now snapshots the EIP-712 message
  parameters (pool_launcher_id, auth_type, chia_network).  ``register_evm_vault``
  uses these snapshotted values (not current settings) to reconstruct the
  digest, so config drift between issuance and verification cannot cause
  signature mismatch or pool-substitution.
"""
from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from .config import get_settings


class ChallengeStoreFullError(Exception):
    """Raised when the in-memory challenge store has hit its max-pending cap.

    The endpoint should translate this into HTTP 429 so the client can
    back off; existing in-flight challenges remain valid.
    """


class RateLimitedError(Exception):
    """Raised when a single source IP has exceeded its per-minute quota."""


@dataclass
class Challenge:
    nonce: str  # 0x-prefixed 32-byte hex
    address: str
    auth_type: str  # "evm" | "chia_bls" | "passkey"
    issued_at: float
    expires_at: float

    # Snapshotted EIP-712 envelope params (POP-CANON-002 fix).
    # The user's signature commits to these exact values; the server uses
    # them at /vault/register/* to rebuild the digest, NOT current settings.
    pool_launcher_id_hex: str = "0x" + "00" * 32
    chia_network: str = "testnet11"


class ChallengeStore:
    """In-memory challenge store.  Thread-safe enough for asyncio single-loop use."""

    def __init__(
        self,
        ttl_seconds: int,
        max_pending: int = 50_000,
        per_ip_per_minute: int = 60,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self.per_ip_per_minute = per_ip_per_minute
        self._challenges: dict[str, Challenge] = {}
        # Per-IP issuance log: deque of timestamps within the last 60s.
        self._ip_issuance: dict[str, deque[float]] = defaultdict(deque)

    def issue(
        self,
        address: str,
        auth_type: str,
        pool_launcher_id_hex: str = "0x" + "00" * 32,
        chia_network: str = "testnet11",
        source_ip: Optional[str] = None,
    ) -> Challenge:
        """Issue a new challenge.

        Raises:
            RateLimitedError: source_ip has exceeded per-minute quota.
            ChallengeStoreFullError: the store has hit max_pending.
        """
        now = time.time()
        self._gc(now)

        if source_ip is not None:
            self._enforce_per_ip_rate(source_ip, now)

        if len(self._challenges) >= self.max_pending:
            raise ChallengeStoreFullError(
                f"Challenge store is at capacity ({self.max_pending}); try again later"
            )

        nonce = "0x" + secrets.token_hex(32)
        ch = Challenge(
            nonce=nonce,
            address=address.lower() if auth_type == "evm" else address,
            auth_type=auth_type,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            pool_launcher_id_hex=pool_launcher_id_hex,
            chia_network=chia_network,
        )
        self._challenges[nonce] = ch
        if source_ip is not None:
            self._ip_issuance[source_ip].append(now)
        return ch

    def pop(self, nonce: str, address: str, auth_type: str) -> Optional[Challenge]:
        """Return and remove the challenge if it is valid for this caller.

        POP-CANON-006 fix: the entry is ALWAYS removed (write-once-read-once),
        whether validation succeeds or fails.  This prevents an attacker
        from filling the store with entries that are never garbage-collected
        because they're never matched by a legitimate caller.
        """
        ch = self._challenges.pop(nonce, None)
        if ch is None:
            return None
        now = time.time()
        if ch.expires_at < now:
            return None
        if ch.auth_type != auth_type:
            return None
        expected = address.lower() if auth_type == "evm" else address
        if ch.address != expected:
            return None
        return ch

    def _gc(self, now: float) -> None:
        stale = [n for n, c in self._challenges.items() if c.expires_at < now]
        for n in stale:
            self._challenges.pop(n, None)
        # Also prune per-IP issuance log of entries older than the window.
        cutoff = now - 60.0
        for ip, dq in list(self._ip_issuance.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                # Drop empty dicts so memory doesn't accumulate per-IP forever.
                self._ip_issuance.pop(ip, None)

    def _enforce_per_ip_rate(self, source_ip: str, now: float) -> None:
        cutoff = now - 60.0
        dq = self._ip_issuance[source_ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.per_ip_per_minute:
            raise RateLimitedError(
                f"IP {source_ip} exceeded {self.per_ip_per_minute} challenges/minute"
            )

    def __len__(self) -> int:
        return len(self._challenges)


_store: Optional[ChallengeStore] = None


def get_store() -> ChallengeStore:
    global _store
    if _store is None:
        s = get_settings()
        _store = ChallengeStore(
            ttl_seconds=s.challenge_ttl_seconds,
            max_pending=s.challenge_store_max_pending,
            per_ip_per_minute=s.challenge_per_ip_per_minute,
        )
    return _store


def reset_store_for_tests() -> None:
    """Reset the module-level store (test-only helper)."""
    global _store
    _store = None
