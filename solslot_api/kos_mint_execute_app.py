"""mTLS-only ASGI surface for the isolated KoS MINT signer."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from .kos_mint_execute_ledger import KosMintExecuteLedger
from .kos_mint_execute_service import (
    KosMintExecuteClaim,
    KosMintExecuteEvidenceError,
    load_kos_mint_execute_artifact,
    load_kos_mint_execute_private_key,
    sign_kos_mint_execute_claim,
)
from .kos_mint_execute_settings import (
    KosMintExecuteSignerSettings,
    get_kos_mint_execute_signer_settings,
)


class KosMintExecuteSignatureResponse(BaseModel):
    requestHash: str
    mintExecuteCosignerPubkey: str
    signature: str


class KosMintExecuteHealthResponse(BaseModel):
    status: str
    network: str
    artifactHash: str
    mintExecuteCosignerPubkey: str
    apiCommit: str
    protocolCommit: str
    ledgerReady: bool


def create_kos_mint_execute_app(
    *,
    settings: KosMintExecuteSignerSettings | None = None,
    ledger: KosMintExecuteLedger | None = None,
) -> FastAPI:
    """Create an application that exposes only health and one fixed signer route.

    Mutual TLS is enforced by ``kos_mint_execute_main`` at the Uvicorn
    listener. The app intentionally has no OpenAPI, docs, or generic signing
    request format for an accidentally exposed service to advertise.
    """
    configured = settings
    configured_ledger = ledger

    def current_settings() -> KosMintExecuteSignerSettings:
        return configured or get_kos_mint_execute_signer_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        signer_settings = current_settings()
        artifact, _ = load_kos_mint_execute_artifact(signer_settings)
        private_key = load_kos_mint_execute_private_key(signer_settings)
        expected = str(artifact["governanceStruct"]["mintExecuteCosignerPubkey"])
        if "0x" + bytes(private_key.get_g1()).hex() != expected.lower():
            raise RuntimeError("KoS signer credential does not match its signed artifact")
        active_ledger = configured_ledger or KosMintExecuteLedger(
            signer_settings.ledger_db_path
        )
        if not active_ledger.healthcheck():
            raise RuntimeError("KoS signer ledger failed SQLite quick_check")
        application.state.kos_mint_execute_ledger = active_ledger
        try:
            yield
        finally:
            if configured_ledger is None:
                active_ledger.close()

    application = FastAPI(
        title="Solslot KoS MINT Execute Signer",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @application.get("/health", response_model=KosMintExecuteHealthResponse)
    def health() -> KosMintExecuteHealthResponse:
        signer_settings = current_settings()
        try:
            artifact, release = load_kos_mint_execute_artifact(signer_settings)
            private_key = load_kos_mint_execute_private_key(signer_settings)
        except KosMintExecuteEvidenceError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        active_ledger: KosMintExecuteLedger = application.state.kos_mint_execute_ledger
        return KosMintExecuteHealthResponse(
            status="healthy",
            network=signer_settings.network,
            artifactHash=str(artifact["artifactHash"]),
            mintExecuteCosignerPubkey="0x" + bytes(private_key.get_g1()).hex(),
            apiCommit=release.apiCommit,
            protocolCommit=release.protocolCommit,
            ledgerReady=active_ledger.healthcheck(),
        )

    @application.post(
        "/v1/governance/mint-execute/sign",
        response_model=KosMintExecuteSignatureResponse,
    )
    def sign(claim: KosMintExecuteClaim) -> KosMintExecuteSignatureResponse:
        signer_settings = current_settings()
        active_ledger: KosMintExecuteLedger = application.state.kos_mint_execute_ledger
        try:
            signature = sign_kos_mint_execute_claim(
                signer_settings, active_ledger, claim
            )
        except KosMintExecuteEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return KosMintExecuteSignatureResponse(
            requestHash=claim.request_hash(),
            mintExecuteCosignerPubkey=claim.mintExecuteCosignerPubkey,
            signature=signature,
        )

    return application


app = create_kos_mint_execute_app()


__all__ = [
    "KosMintExecuteHealthResponse",
    "KosMintExecuteSignatureResponse",
    "app",
    "create_kos_mint_execute_app",
]
