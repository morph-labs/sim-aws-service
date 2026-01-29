from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Header, HTTPException, status


@dataclass(frozen=True)
class CallerContext:
    morph_api_key: str
    morph_authorization_header: str
    user_id: str | None
    org_id: str | None

    @property
    def tenant_id(self) -> str:
        if self.org_id:
            return self.org_id
        if self.user_id:
            return self.user_id
        return "unknown"


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
    morph_api_key = _parse_bearer(authorization)
    return CallerContext(
        morph_api_key=morph_api_key,
        morph_authorization_header=f"Bearer {morph_api_key}",
        user_id=user_id,
        org_id=org_id,
    )
