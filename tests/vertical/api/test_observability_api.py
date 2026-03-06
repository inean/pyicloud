from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/v1/auth/challenge",
        json={"username": "success@example.com", "password_envelope": "secret"},
    )
    assert login.status_code == 200
    token = login.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_observability_api_default_null_adapter(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        promql = await client.post("/v1/observability/promql", headers=headers, json={"query": "up"})
        assert promql.status_code == 200
        promql_payload = promql.json()["data"]
        assert promql_payload["status"] == "unconfigured"
        assert promql_payload["language"] == "promql"

        pronql = await client.post("/v1/observability/pronql", headers=headers, json={"query": "up"})
        assert pronql.status_code == 404


@pytest.mark.asyncio
async def test_observability_api_range_query(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        response = await client.post(
            "/v1/observability/logql",
            headers=headers,
            json={
                "query": '{service="api"}',
                "start": 1710000000,
                "end": 1710000600,
                "step": "1m",
            },
        )
        assert response.status_code == 200
        payload = response.json()["data"]
        assert payload["language"] == "logql"
        assert payload["data"]["resultType"] == "matrix"


@pytest.mark.asyncio
async def test_observability_api_validates_range_fields(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        invalid = await client.post(
            "/v1/observability/traceql",
            headers=headers,
            json={"query": '{ .service.name = "api" }', "start": 1710000000},
        )
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == "validation_error"
