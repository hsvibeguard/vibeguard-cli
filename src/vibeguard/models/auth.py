"""Authentication and authorization models for Pro licensing."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AuthToken(BaseModel):
    """Cached authentication token from the license server."""

    token: str
    expires_at: datetime
    entitlements: list[str] = Field(default_factory=list)
    license_id: str | None = None
    plan: str | None = None
    last_refresh: datetime | None = None


class MachineInfo(BaseModel):
    """Machine identification for license activation."""

    machine_id: str
    created_at: datetime


class AuthCache(BaseModel):
    """Complete auth cache file structure stored in ~/.vibeguard/auth.json."""

    version: int = 1
    token: AuthToken | None = None
    machine: MachineInfo


class ActivateRequest(BaseModel):
    """Request body for POST /v1/licenses/activate."""

    license_key: str
    machine_id: str


class ActivateResponse(BaseModel):
    """Response from POST /v1/licenses/activate."""

    token: str
    expires_at: datetime
    entitlements: list[str] = Field(default_factory=list)
    plan: str | None = None
    license_id: str | None = None


class RefreshResponse(BaseModel):
    """Response from POST /v1/licenses/refresh-token."""

    token: str
    expires_at: datetime
    entitlements: list[str] = Field(default_factory=list)


class EntitlementsResponse(BaseModel):
    """Response from GET /v1/entitlements."""

    entitlements: list[str]
    plan: str | None = None
    expires_at: datetime | None = None


class Bundle(BaseModel):
    """Policy bundle containing prompts and patch rules."""

    version: str
    prompts: dict[str, str] = Field(default_factory=dict)
    patch_rules: dict = Field(default_factory=dict)
    defaults: dict = Field(default_factory=dict)


class BundleMetadata(BaseModel):
    """Bundle cache metadata for tracking downloaded bundles."""

    version: str
    downloaded_at: datetime
    sha256: str | None = None
    is_current: bool = False


class ApiError(BaseModel):
    """Error response from the API."""

    error: str
    code: str | None = None
    detail: str | None = None
