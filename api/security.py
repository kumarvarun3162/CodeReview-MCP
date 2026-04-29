import hmac
import hashlib
from fastapi import Request, HTTPException
from core.config import settings


async def verify_github_signature(request: Request) -> bytes:
    """
    Verifies that an incoming request actually came from GitHub.

    How it works:
    1. When you set up the webhook on GitHub, you give it a secret string.
    2. GitHub uses that secret to create an HMAC-SHA256 signature of the request body.
    3. It sends that signature in the X-Hub-Signature-256 header.
    4. We recreate the signature ourselves using the same secret.
    5. If they match → request is genuine. If not → reject it.
    """
    signature_header = request.headers.get("X-Hub-Signature-256")

    if not signature_header:
        raise HTTPException(
            status_code=403,
            detail="Missing X-Hub-Signature-256 header. Request not from GitHub."
        )

    body = await request.body()

    # Recreate the signature using our webhook secret
    expected_signature = "sha256=" + hmac.new(
        key=settings.github_webhook_secret.encode("utf-8"),
        msg=body,
        digestmod=hashlib.sha256
    ).hexdigest()

    # Compare using hmac.compare_digest (prevents timing attacks)
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(
            status_code=403,
            detail="Signature mismatch. Request may be forged."
        )

    return body