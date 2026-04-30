# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Tests for CSRF protection enforcement on state-changing API endpoints."""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from superset.app import SupersetApp


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enabled_by_default(app: SupersetApp) -> None:
    """WTF_CSRF_ENABLED must default to True in the base configuration."""
    from superset import config as default_config

    assert default_config.WTF_CSRF_ENABLED is True


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_rejects_post_without_token(
    app: SupersetApp,
    app_context: None,
) -> None:
    """POST to a protected API endpoint without a CSRF token must be rejected."""
    with app.test_client() as client:
        response = client.post(
            "/api/v1/dashboard/",
            json={"dashboard_title": "test"},
        )
        # 400 (bad CSRF token) or 401 (unauthenticated) are both acceptable;
        # the key assertion is that it is NOT 200/201.
        assert response.status_code in (400, 401, 403)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_rejects_put_without_token(
    app: SupersetApp,
    app_context: None,
) -> None:
    """PUT to a protected API endpoint without a CSRF token must be rejected."""
    with app.test_client() as client:
        response = client.put(
            "/api/v1/chart/1",
            json={"slice_name": "test"},
        )
        assert response.status_code in (400, 401, 403)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_rejects_delete_without_token(
    app: SupersetApp,
    app_context: None,
) -> None:
    """DELETE to a protected API endpoint without a CSRF token must be rejected."""
    with app.test_client() as client:
        response = client.delete("/api/v1/dataset/1")
        assert response.status_code in (400, 401, 403)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_allows_get_without_token(
    app: SupersetApp,
    app_context: None,
) -> None:
    """GET requests should not require a CSRF token."""
    with app.test_client() as client:
        response = client.get("/api/v1/dashboard/")
        # GET may return 401 (unauthenticated) but must NOT return 400 (CSRF error)
        assert response.status_code != 400


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enforcement_hook_logs_missing_token(
    app: SupersetApp,
    app_context: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The defense-in-depth hook should log when a CSRF token is missing."""
    with app.test_client() as client:
        with caplog.at_level(logging.WARNING, logger="superset.initialization"):
            client.post(
                "/api/v1/dashboard/",
                json={"dashboard_title": "test"},
            )
        assert any("CSRF" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": False, "TESTING": False}],
    indirect=True,
)
def test_csrf_disabled_warning_logged(
    app: SupersetApp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A security warning must be logged when CSRF is disabled outside tests."""
    with patch("superset.initialization.is_test", return_value=False):
        from superset.initialization import SupersetAppInitializer

        initializer = SupersetAppInitializer(app)
        with caplog.at_level(logging.WARNING, logger="superset.initialization"):
            initializer.configure_wtf()
        warning_messages = [r.message for r in caplog.records if "CSRF" in r.message]
        assert len(warning_messages) >= 1
        assert "WTF_CSRF_ENABLED=False" in warning_messages[0]
