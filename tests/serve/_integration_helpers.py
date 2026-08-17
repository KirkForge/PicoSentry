"""Shared helpers for the split test_integration_* files.

These were originally module-level functions in tests/serve/test_integration.py;
the file was split in three so pytest-xdist ``--dist=loadfile`` can spread its
~150s of test time across workers instead of pinning it to one. Bodies are
unchanged — this module only holds the plumbing the three files share.
"""

import time

from picosentry.serve.services.auth import AuthService


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def _register_and_login(client, role="admin", suffix=None):
    """One-shot: create a user at the requested role + login → token, and
    create a default org so org-scoped endpoints have a tenant context.

    The ``/auth/register`` endpoint creates viewers only (P0 fix); for
    ``admin`` and ``operator`` we drop down to the service layer so the
    integration tests can still exercise elevated paths.
    """
    tag = suffix or int(time.time() * 1000)
    username = f"integ_{role}_{tag}"
    password = "IntegrationTest123!"

    if role == "viewer":
        client.post("/auth/register", json={"username": username, "password": password})
    else:
        AuthService().create_user(username, password, role=role)

    resp = client.post("/auth/login", json={"username": username, "password": password})
    token = resp.json().get("access_token", "") if resp.status_code == 200 else ""
    assert token, f"Login failed for {username}"

    slug = f"integ-org-{role}-{tag}"
    resp = client.post(
        "/orgs",
        json={"name": f"Integration Org {role} {tag}", "slug": slug},
        headers=_auth_headers(token),
    )
    assert resp.status_code in (201, 409), f"Default org creation failed: {resp.text}"

    return token, username


def _register_with_org(client, role="operator", slug_prefix="tenant", tag=None):
    """Register a user (via _register_and_login) and create ONE additional org
    on top of the default org the helper already creates. Returns
    (token, new_org_id, slug). Used by the tenant-isolation tests which all
    need two labeled orgs to assert isolation between them.
    """
    tag = tag or int(time.time() * 1000)
    token, _ = _register_and_login(client, role=role, suffix=tag)
    slug = f"{slug_prefix}-{tag}"
    resp = client.post("/orgs", json={"name": slug, "slug": slug}, headers=_auth_headers(token))
    assert resp.status_code == 201, resp.text
    return token, resp.json()["id"], slug


def _starlette_app_with(middleware_cls, **mw_kwargs):
    """Build a 1-route Starlette app with the given middleware → TestClient.

    Shared by the three middleware smoke tests (rate-limit / CORS / DDoS).
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def home(_request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home)])
    app.add_middleware(middleware_cls, **mw_kwargs)
    return TestClient(app)
