"""Environment-provisioned bearer authentication for the demo console API."""
from __future__ import annotations

import hmac
import os
from typing import Dict

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_auth = HTTPBearer(auto_error=False)


def authenticated_role(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth),
) -> Dict[str, str]:
    operator_token = os.getenv("OPERATOR_TOKEN", "")
    admin_token = os.getenv("ADMIN_TOKEN", "")
    if not operator_token and not admin_token:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured; protected routes are unavailable.",
        )
    if (
        operator_token
        and admin_token
        and hmac.compare_digest(operator_token, admin_token)
    ):
        raise HTTPException(
            status_code=503,
            detail="Operator and administrator tokens must be distinct.",
        )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    supplied = credentials.credentials
    if admin_token and hmac.compare_digest(supplied, admin_token):
        return {"role": "admin"}
    if operator_token and hmac.compare_digest(supplied, operator_token):
        return {"role": "operator"}
    raise HTTPException(
        status_code=401,
        detail="Bearer token is invalid.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_operator(identity: Dict[str, str] = Depends(authenticated_role)) -> Dict[str, str]:
    if identity["role"] not in {"operator", "admin"}:
        raise HTTPException(status_code=403, detail="Operator role is required.")
    return identity


def require_admin(identity: Dict[str, str] = Depends(authenticated_role)) -> Dict[str, str]:
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role is required.")
    return identity
