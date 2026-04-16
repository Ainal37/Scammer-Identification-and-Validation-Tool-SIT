"""Role-Based Access Control dependency factory."""

from fastapi import Depends, HTTPException
from .security import get_current_admin


def require_role(*allowed_roles):
    """Return a FastAPI dependency that enforces role membership.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_role("admin"))])
        def admin_endpoint(): ...

    Or inject the user:
        def endpoint(admin=Depends(require_role("admin", "editor"))): ...
    """
    def _dependency(admin=Depends(get_current_admin)):
        if admin.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role: {', '.join(allowed_roles)}. You have: {admin.role}",
            )
        return admin
    return _dependency
