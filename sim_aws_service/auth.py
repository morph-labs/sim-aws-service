from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated

from fastapi import Header, HTTPException, status


@dataclass(frozen=True)
class CallerContext:
    user_api_key: str
    user_authorization_header: str
    user_id: str | None
    org_id: str | None

    @property
    def api_key_hash(self) -> str:
        # Stable, non-reversible identifier for the caller (avoid storing raw keys in DB).
        digest = hashlib.sha256(self.user_api_key.encode("utf-8")).hexdigest()
        return f"keysha256_{digest}"


def _parse_bearer(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    prefix = "Bearer "
    if not authorization.startswith(prefix) or len(authorization) <= len(prefix):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header; expected Bearer token",
        )
    return authorization[len(prefix) :].strip()


async def get_caller(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    org_id: Annotated[str | None, Header(alias="X-Morph-Org-Id")] = None,
    user_id: Annotated[str | None, Header(alias="X-Morph-User-Id")] = None,
) -> CallerContext:
    user_api_key = _parse_bearer(authorization)
    return CallerContext(
        user_api_key=user_api_key,
        user_authorization_header=f"Bearer {user_api_key}",
        user_id=user_id,
        org_id=org_id,
    )
