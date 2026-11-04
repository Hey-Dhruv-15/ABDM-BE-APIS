"""
Main API Router.
Gathers all sub-routers and combines them into one main API router.
"""
from fastapi import APIRouter, Depends

from app.api.routes import abdm
from app.api.dependencies import get_security_headers_for_docs

_docs_security_dependencies = [Depends(get_security_headers_for_docs)]
api_router = APIRouter(dependencies=_docs_security_dependencies)

api_router.include_router(abdm.router, dependencies=_docs_security_dependencies)
