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
import logging
from typing import Any

import pytest
from flask.testing import FlaskClient

from superset.extensions import csrf


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_exempt_blueprints(app_context: None) -> None:
    """
    Test that only FAB security API blueprints (which use token-based auth)
    are exempt from CSRF protection.
    """
    assert {blueprint.name for blueprint in csrf._exempt_blueprints} == {
        "SupersetGroupApi",
        "MenuApi",
        "SecurityApi",
        "OpenApi",
        "PermissionViewMenuApi",
        "SupersetRoleApi",
        "SupersetUserApi",
        "PermissionApi",
        "ViewMenuApi",
    }


@pytest.mark.parametrize(
    "app",
    [
        {
            "WTF_CSRF_ENABLED": True,
            "FAB_API_KEY_ENABLED": True,
        }
    ],
    indirect=True,
)
def test_csrf_exempt_blueprints_with_api_key(app: Any, app_context: None) -> None:
    """
    Test that ApiKeyApi blueprint is CSRF-exempt when FAB_API_KEY_ENABLED
    config is enabled.
    """
    assert "ApiKeyApi" in {blueprint.name for blueprint in csrf._exempt_blueprints}


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": False}],
    indirect=True,
)
def test_csrf_disabled_logs_warning(
    app: Any, app_context: None, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that disabling CSRF protection emits a security warning at startup.
    """
    with caplog.at_level(logging.WARNING):
        # Re-run configure_wtf to capture the warning
        from superset.initialization import SupersetAppInitializer

        initializer = SupersetAppInitializer(app)
        initializer.configure_wtf()

    assert any(
        "CSRF protection is disabled" in record.message for record in caplog.records
    )


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enforcement_logs_missing_token(
    client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that the CSRF enforcement middleware logs a warning when a
    state-changing API request is made without a CSRF token.
    """
    with caplog.at_level(logging.WARNING):
        client.post("/api/v1/dashboard/", json={"dashboard_title": "test"})

    assert any(
        "CSRF token missing on POST /api/v1/dashboard/" in record.message
        for record in caplog.records
    )


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enforcement_skips_bearer_auth(
    client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that the CSRF enforcement middleware skips requests with
    Bearer token auth (which is immune to CSRF).
    """
    with caplog.at_level(logging.WARNING):
        client.post(
            "/api/v1/dashboard/",
            json={"dashboard_title": "test"},
            headers={"Authorization": "Bearer fake-token"},
        )

    assert not any("CSRF token missing" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enforcement_skips_safe_methods(
    client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that the CSRF enforcement middleware does not flag safe
    (read-only) HTTP methods.
    """
    with caplog.at_level(logging.WARNING):
        client.get("/api/v1/dashboard/")

    assert not any("CSRF token missing" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enforcement_covers_mutation_methods(
    client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that the CSRF enforcement middleware logs warnings for all
    state-changing HTTP methods (POST, PUT, DELETE, PATCH).
    """
    methods = ["POST", "PUT", "DELETE", "PATCH"]
    for method in methods:
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            getattr(client, method.lower())(
                "/api/v1/dashboard/1",
                json={},
            )
        assert any(
            "CSRF token missing" in record.message for record in caplog.records
        ), f"Expected CSRF warning for {method} but none was logged"
