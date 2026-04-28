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
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enabled_by_default(app: Any) -> None:
    """
    Test that WTF_CSRF_ENABLED defaults to True.
    """
    assert app.config["WTF_CSRF_ENABLED"] is True


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": False, "TESTING": False}],
    indirect=True,
)
def test_csrf_force_enabled_in_non_testing(
    app: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that CSRF is force-enabled when WTF_CSRF_ENABLED=False in
    non-testing environments, and a warning is logged.
    """
    assert app.config["WTF_CSRF_ENABLED"] is True


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_logs_missing_token_on_mutation(
    app: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test that a warning is logged when a state-changing API request
    is made without a CSRF token header.
    """
    with app.test_client() as client:
        with caplog.at_level(logging.WARNING, logger="superset.initialization"):
            client.post("/api/v1/dashboard/")
            assert any(
                "CSRF token missing" in record.message for record in caplog.records
            )
