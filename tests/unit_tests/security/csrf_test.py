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
from flask import Response

from superset.app import SupersetApp
from superset.extensions import csrf
from superset.utils import json as json_utils


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": False}],
    indirect=True,
)
def test_csrf_always_initialized(app: SupersetApp, app_context: None) -> None:
    """
    CSRF infrastructure is initialized even when WTF_CSRF_ENABLED is False,
    so that the require_csrf decorator can validate tokens independently.
    """
    # Exempt lists are populated only after init_app() has run.
    assert csrf._exempt_views is not None


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": False}],
    indirect=True,
)
def test_csrf_disabled_logs_warning(
    app: SupersetApp, app_context: None, caplog: pytest.LogCaptureFixture
) -> None:
    """
    A warning is emitted when CSRF global enforcement is turned off.
    """
    with caplog.at_level(logging.WARNING):
        from superset.initialization import SupersetAppInitializer

        initializer = SupersetAppInitializer(app)
        initializer.configure_wtf()
    assert any("WTF_CSRF_ENABLED is set to False" in msg for msg in caplog.messages)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_enabled_no_warning(
    app: SupersetApp, app_context: None, caplog: pytest.LogCaptureFixture
) -> None:
    """
    No warning is emitted when CSRF is properly enabled.
    """
    with caplog.at_level(logging.WARNING):
        from superset.initialization import SupersetAppInitializer

        initializer = SupersetAppInitializer(app)
        initializer.configure_wtf()
    assert not any("WTF_CSRF_ENABLED is set to False" in msg for msg in caplog.messages)


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_require_csrf_rejects_missing_token_on_browser_session(
    app: SupersetApp,
    app_context: None,
) -> None:
    """
    The require_csrf decorator rejects state-changing requests from browser
    sessions (identified by the presence of a session cookie) that lack a
    valid CSRF token.
    """
    from superset.views.base_api import require_csrf

    @require_csrf
    def dummy_post(self: Any) -> Response:
        return Response("ok", status=200)

    class FakeView:
        @staticmethod
        def response(status_code: int, **kwargs: Any) -> Response:
            return Response(
                json_utils.dumps(kwargs),
                status=status_code,
                content_type="application/json",
            )

    with app.test_request_context(
        "/api/v1/dashboard/",
        method="POST",
        content_type="application/json",
    ):
        from flask import request as flask_request

        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
        flask_request.cookies = {cookie_name: "fake-session-value"}

        resp = dummy_post(FakeView())
        assert resp.status_code == 400
        assert b"CSRF token missing or invalid" in resp.data


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_require_csrf_allows_non_browser_requests(
    app: SupersetApp,
    app_context: None,
) -> None:
    """
    API-token requests (no session cookie) bypass the require_csrf check
    because the bearer token itself proves intent.
    """
    from superset.views.base_api import require_csrf

    @require_csrf
    def dummy_delete(self: Any, pk: int) -> Response:
        return Response("deleted", status=200)

    class FakeView:
        pass

    with app.test_request_context(
        "/api/v1/dataset/1",
        method="DELETE",
        content_type="application/json",
    ):
        resp = dummy_delete(FakeView(), pk=1)
        assert resp.status_code == 200


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_require_csrf_skips_get_requests(
    app: SupersetApp,
    app_context: None,
) -> None:
    """
    GET requests are not state-changing and should pass through without
    CSRF validation.
    """
    from superset.views.base_api import require_csrf

    @require_csrf
    def dummy_get(self: Any) -> Response:
        return Response("ok", status=200)

    class FakeView:
        pass

    with app.test_request_context(
        "/api/v1/chart/",
        method="GET",
    ):
        from flask import request as flask_request

        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
        flask_request.cookies = {cookie_name: "fake-session-value"}

        resp = dummy_get(FakeView())
        assert resp.status_code == 200
