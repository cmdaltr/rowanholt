"""
Webhook Routes

Webhooks, for admins: register a URL and the events it wants, see the last deliveries, and send a
test. Registering and listing are open on every edition; sending is the automation feature, checked
when something is sent (webhooks.sending), and this API says when they aren't sending and why.
"""

import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

try:
    from . import licence, webhooks
    from .auth import access
except ImportError:
    import licence
    import webhooks
    from auth import access

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class WebhookIn(BaseModel):
    url: str = Field(min_length=1, max_length=2000)
    events: List[str]
    secret: Optional[str] = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=200)


class WebhookEdit(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2000)
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None
    description: Optional[str] = Field(default=None, max_length=200)


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _find(hook_id: str) -> Dict:
    hook = next((h for h in webhooks.hooks() if h["id"] == hook_id), None)
    if not hook:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such webhook")
    return hook


@router.get("")
async def list_webhooks(admin: dict = Depends(access.require_admin)) -> Dict:
    on, why = webhooks.sending()
    return {"events": list(webhooks.EVENTS), "webhooks": [webhooks.public(h) for h in webhooks.hooks()],
            "sending": on, "reason": why}


@router.post("")
async def create_webhook(body: WebhookIn, request: Request, admin: dict = Depends(access.require_admin)) -> Dict:
    """The secret is generated when not given, and returned once here; afterwards the API only says
    whether there is one."""
    problem = webhooks.validate(body.url, body.events)
    if problem:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)
    hook = webhooks.add(body.url, body.events, body.secret, body.description)
    licence.audit("webhook_created", admin, _ip(request), resource_type="webhook", resource_id=hook["id"],
                  url=hook["url"], events=hook["events"])
    return {**webhooks.public(hook), "secret": hook["secret"]}


@router.patch("/{hook_id}")
async def edit_webhook(hook_id: str, body: WebhookEdit, request: Request,
                       admin: dict = Depends(access.require_admin)) -> Dict:
    current = _find(hook_id)
    problem = webhooks.validate(body.url if body.url is not None else current["url"],
                                body.events if body.events is not None else current["events"])
    if problem:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)
    fields = {k: v for k, v in body.dict().items() if v is not None}
    hook = webhooks.update(hook_id, **fields)
    licence.audit("webhook_changed", admin, _ip(request), resource_type="webhook", resource_id=hook_id, **fields)
    return webhooks.public(hook)


@router.delete("/{hook_id}")
async def delete_webhook(hook_id: str, request: Request, admin: dict = Depends(access.require_admin)) -> Dict:
    if not webhooks.remove(hook_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such webhook")
    licence.audit("webhook_deleted", admin, _ip(request), resource_type="webhook", resource_id=hook_id)
    return {"deleted": hook_id}


@router.post("/{hook_id}/test")
async def test_webhook(hook_id: str, admin: dict = Depends(access.require_admin)) -> Dict:
    """Send a job.completed for a made-up job now, once, and wait for the answer. A test is a
    delivery, so it's sent only when this edition sends webhooks."""
    hook = _find(hook_id)
    on, why = webhooks.sending()
    if not on:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, why)
    data = {"job_id": "test", "case_number": "Rowanholt webhook test", "status": "completed", "images": 0,
            "test": True}
    return await asyncio.to_thread(webhooks.deliver, hook, "job.completed", data, 1)
