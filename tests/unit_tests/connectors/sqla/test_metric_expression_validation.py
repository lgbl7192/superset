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

"""Tests for SqlMetric expression validation against SQL injection."""

from unittest.mock import MagicMock

import pytest

from superset.connectors.sqla.models import SqlMetric
from superset.exceptions import QueryObjectValidationError


def _make_metric(expression: str) -> SqlMetric:
    """Create a SqlMetric with a mock table/database for testing."""
    metric = SqlMetric(metric_name="test_metric", expression=expression)
    metric.table = MagicMock()
    metric.table.database.backend = "postgresql"
    metric.table.database.make_sqla_column_compatible = lambda col, label: col
    return metric


@pytest.mark.parametrize(
    "expression",
    [
        "COUNT(*)",
        "SUM(amount)",
        "AVG(price)",
        "MAX(created_at)",
        "COUNT(DISTINCT user_id)",
        "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)",
    ],
)
def test_valid_metric_expressions_pass(expression: str) -> None:
    """Legitimate metric expressions are accepted."""
    metric = _make_metric(expression)
    # Should not raise
    metric.get_sqla_col()


@pytest.mark.parametrize(
    "expression",
    [
        "SUM(1); SELECT pg_sleep(5)--",
        "COUNT(*); DROP TABLE users--",
        "1; INSERT INTO audit VALUES('pwned')--",
    ],
)
def test_stacked_statements_rejected(expression: str) -> None:
    """Stacked SQL statements in metric expressions are rejected."""
    metric = _make_metric(expression)
    with pytest.raises(QueryObjectValidationError):
        metric.get_sqla_col()
