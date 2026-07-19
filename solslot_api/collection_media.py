"""Verified S3 staging and IPFS pinning for collection media."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .config import Settings


class MediaPipelineUnavailable(RuntimeError):
    pass


class MediaVerificationError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedMedia:
    sha256: str
    mime_type: str
    byte_size: int
    https_url: str
    cid: str
    malware_status: str
    availability_status: str


class CollectionMediaPipeline:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport

    def presign_upload(
        self,
        *,
        collection_id: str,
        asset_id: str,
        filename: str,
    ) -> dict[str, Any]:
        self._require_s3()
        extension = ""
        if "." in filename:
            candidate = filename.rsplit(".", 1)[1].lower()
            if candidate.isalnum() and len(candidate) <= 12:
                extension = "." + candidate
        object_key = (
            f"collections/{_safe_segment(collection_id)}/"
            f"{_safe_segment(asset_id)}{extension}"
        )
        expires = self.settings.collection_s3_presign_ttl_seconds
        return {
            "objectKey": object_key,
            "uploadUrl": self._s3_signed_url("PUT", object_key, expires),
            "method": "PUT",
            "headers": {},
            "expiresIn": expires,
        }

    async def verify_and_pin(
        self,
        *,
        object_key: str,
        expected_sha256: str,
        expected_mime_type: str,
        expected_byte_size: int,
        asset_name: str,
    ) -> VerifiedMedia:
        self._require_all()
        timeout = self.settings.collection_asset_verification_timeout_seconds
        download_url = self._s3_signed_url("GET", object_key, 300)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            response = await client.get(download_url)
            response.raise_for_status()
            payload = response.content
            if len(payload) > self.settings.collection_asset_max_bytes:
                raise MediaVerificationError("uploaded object exceeds the configured size cap")
            actual_sha256 = hashlib.sha256(payload).hexdigest()
            actual_mime = _detect_mime(payload)
            if len(payload) != expected_byte_size:
                raise MediaVerificationError(
                    f"byte-size mismatch: expected {expected_byte_size}, got {len(payload)}"
                )
            if actual_sha256 != expected_sha256.lower():
                raise MediaVerificationError("SHA-256 mismatch")
            if actual_mime != expected_mime_type.lower():
                raise MediaVerificationError(
                    f"MIME mismatch: declared {expected_mime_type}, detected {actual_mime}"
                )

            await self._scan(client, payload, actual_sha256, actual_mime)
            cid = await self._add_to_ipfs(client, payload, asset_name)
            await self._pin_cid(client, cid, asset_name, actual_sha256)

            https_url = self._public_s3_url(object_key)
            await self._verify_remote_bytes(client, https_url, actual_sha256)
            gateway_url = self._gateway_url(cid)
            await self._verify_remote_bytes(client, gateway_url, actual_sha256)

        return VerifiedMedia(
            sha256=actual_sha256,
            mime_type=actual_mime,
            byte_size=len(payload),
            https_url=https_url,
            cid=cid,
            malware_status="CLEAN",
            availability_status="HEALTHY",
        )

    async def _scan(
        self,
        client: httpx.AsyncClient,
        payload: bytes,
        digest: str,
        mime_type: str,
    ) -> None:
        headers = {
            "content-type": mime_type,
            "x-content-sha256": digest,
        }
        if self.settings.collection_malware_scan_token:
            headers["authorization"] = (
                "Bearer " + self.settings.collection_malware_scan_token
            )
        response = await client.post(
            str(self.settings.collection_malware_scan_url),
            headers=headers,
            content=payload,
        )
        response.raise_for_status()
        try:
            status = str(response.json()["status"]).upper()
        except (KeyError, TypeError, ValueError) as exc:
            raise MediaVerificationError("malware scanner returned an invalid response") from exc
        if status != "CLEAN":
            raise MediaVerificationError(f"malware scan did not pass: {status}")

    async def _add_to_ipfs(
        self,
        client: httpx.AsyncClient,
        payload: bytes,
        name: str,
    ) -> str:
        url = str(self.settings.collection_ipfs_api_url).rstrip("/") + "/api/v0/add"
        response = await client.post(
            url,
            params={"cid-version": "1", "raw-leaves": "true", "pin": "false"},
            files={"file": (name, payload, "application/octet-stream")},
        )
        response.raise_for_status()
        try:
            lines = [line for line in response.text.splitlines() if line.strip()]
            cid = str(json.loads(lines[-1])["Hash"])
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MediaVerificationError("IPFS add endpoint returned no CID") from exc
        if len(cid) < 10:
            raise MediaVerificationError("IPFS add endpoint returned an invalid CID")
        return cid

    async def _pin_cid(
        self,
        client: httpx.AsyncClient,
        cid: str,
        name: str,
        digest: str,
    ) -> None:
        headers = {
            "authorization": "Bearer " + str(self.settings.collection_ipfs_pinning_token),
            "content-type": "application/json",
        }
        response = await client.post(
            str(self.settings.collection_ipfs_pinning_service_url).rstrip("/") + "/pins",
            headers=headers,
            json={"cid": cid, "name": name, "meta": {"sha256": digest}},
        )
        response.raise_for_status()
        try:
            returned_cid = str(response.json()["pin"]["cid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MediaVerificationError("pinning service returned an invalid response") from exc
        if returned_cid != cid:
            raise MediaVerificationError("pinning service acknowledged a different CID")

    async def _verify_remote_bytes(
        self,
        client: httpx.AsyncClient,
        url: str,
        expected_sha256: str,
    ) -> None:
        response = await client.get(url)
        response.raise_for_status()
        if hashlib.sha256(response.content).hexdigest() != expected_sha256:
            raise MediaVerificationError(f"availability endpoint served altered bytes: {url}")

    def _public_s3_url(self, object_key: str) -> str:
        return (
            str(self.settings.collection_s3_public_base_url).rstrip("/")
            + "/"
            + "/".join(quote(part, safe="-_.~") for part in object_key.split("/"))
        )

    def _gateway_url(self, cid: str) -> str:
        base = str(self.settings.collection_ipfs_gateway_url)
        if "{cid}" in base:
            return base.format(cid=quote(cid, safe="-_.~"))
        return base.rstrip("/") + "/ipfs/" + quote(cid, safe="-_.~")

    def _s3_signed_url(self, method: str, object_key: str, expires: int) -> str:
        self._require_s3()
        endpoint = urlparse(str(self.settings.collection_s3_endpoint_url))
        if endpoint.scheme not in ("http", "https") or not endpoint.netloc:
            raise MediaPipelineUnavailable("collection S3 endpoint must be an HTTP(S) URL")
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        region = self.settings.collection_s3_region
        service = "s3"
        scope = f"{date_stamp}/{region}/{service}/aws4_request"
        credential = f"{self.settings.collection_s3_access_key_id}/{scope}"
        path_prefix = endpoint.path.rstrip("/")
        path_parts = [self.settings.collection_s3_bucket, *object_key.split("/")]
        canonical_uri = path_prefix + "/" + "/".join(
            quote(part, safe="-_.~") for part in path_parts
        )
        params = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": credential,
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": str(expires),
            "X-Amz-SignedHeaders": "host",
        }
        canonical_query = "&".join(
            f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
            for key, value in sorted(params.items())
        )
        canonical_headers = f"host:{endpoint.netloc.lower()}\n"
        canonical_request = "\n".join(
            [method.upper(), canonical_uri, canonical_query, canonical_headers, "host", "UNSIGNED-PAYLOAD"]
        )
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = _signature_key(
            str(self.settings.collection_s3_secret_access_key),
            date_stamp,
            region,
            service,
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return (
            f"{endpoint.scheme}://{endpoint.netloc}{canonical_uri}?"
            f"{canonical_query}&X-Amz-Signature={signature}"
        )

    def _require_s3(self) -> None:
        missing = [
            name
            for name, value in (
                ("S3 endpoint", self.settings.collection_s3_endpoint_url),
                ("S3 access key", self.settings.collection_s3_access_key_id),
                ("S3 secret key", self.settings.collection_s3_secret_access_key),
                ("S3 public URL", self.settings.collection_s3_public_base_url),
            )
            if not value
        ]
        if missing:
            raise MediaPipelineUnavailable(
                "collection object storage is not configured: " + ", ".join(missing)
            )

    def _require_all(self) -> None:
        self._require_s3()
        missing = [
            name
            for name, value in (
                ("IPFS API", self.settings.collection_ipfs_api_url),
                ("IPFS pinning service", self.settings.collection_ipfs_pinning_service_url),
                ("IPFS pinning token", self.settings.collection_ipfs_pinning_token),
                ("IPFS gateway", self.settings.collection_ipfs_gateway_url),
                ("malware scanner", self.settings.collection_malware_scan_url),
            )
            if not value
        ]
        if missing:
            raise MediaPipelineUnavailable(
                "collection verification services are not configured: " + ", ".join(missing)
            )


def _signature_key(secret: str, date: str, region: str, service: str) -> bytes:
    date_key = hmac.new(("AWS4" + secret).encode(), date.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, service.encode(), hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def _safe_segment(value: str) -> str:
    cleaned = "".join(char for char in value if char.isalnum() or char in "-_.")
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError("collection and asset ids must contain URL-safe characters")
    return cleaned[:160]


def _detect_mime(payload: bytes) -> str:
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if payload.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WEBP":
        return "image/webp"
    if payload.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if payload.startswith(b"%PDF-"):
        return "application/pdf"
    raise MediaVerificationError("unsupported or unrecognized media bytes")


__all__ = [
    "CollectionMediaPipeline",
    "MediaPipelineUnavailable",
    "MediaVerificationError",
    "VerifiedMedia",
]
