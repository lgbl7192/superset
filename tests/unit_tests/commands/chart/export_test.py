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
"""Unit tests for ExportChartsCommand per-object access control."""

import pytest
from pytest_mock import MockerFixture

from superset.commands.chart.exceptions import ChartAccessDeniedError
from superset.commands.chart.export import ExportChartsCommand


def test_export_charts_validate_denies_inaccessible_chart(
    mocker: MockerFixture,
) -> None:
    """Exporting a chart the user cannot access raises ChartAccessDeniedError."""
    mock_chart = mocker.MagicMock()
    mock_chart.id = 42

    mocker.patch.object(ExportChartsCommand, "dao", new=mocker.MagicMock())
    mocker.patch.object(
        ExportChartsCommand.dao, "find_by_ids", return_value=[mock_chart]
    )

    mock_sm = mocker.patch(
        "superset.commands.chart.export.security_manager",
    )
    mock_sm.can_access_chart.return_value = False

    cmd = ExportChartsCommand([42])
    with pytest.raises(ChartAccessDeniedError):
        cmd.validate()

    mock_sm.can_access_chart.assert_called_once_with(mock_chart)


def test_export_charts_validate_allows_accessible_chart(
    mocker: MockerFixture,
) -> None:
    """Exporting a chart the user can access passes validation."""
    mock_chart = mocker.MagicMock()
    mock_chart.id = 1

    mocker.patch.object(ExportChartsCommand, "dao", new=mocker.MagicMock())
    mocker.patch.object(
        ExportChartsCommand.dao, "find_by_ids", return_value=[mock_chart]
    )

    mock_sm = mocker.patch(
        "superset.commands.chart.export.security_manager",
    )
    mock_sm.can_access_chart.return_value = True

    cmd = ExportChartsCommand([1])
    cmd.validate()

    mock_sm.can_access_chart.assert_called_once_with(mock_chart)


def test_export_charts_validate_denies_if_any_chart_inaccessible(
    mocker: MockerFixture,
) -> None:
    """If one chart in a batch is inaccessible, validation fails."""
    accessible_chart = mocker.MagicMock()
    accessible_chart.id = 1
    inaccessible_chart = mocker.MagicMock()
    inaccessible_chart.id = 2

    mocker.patch.object(ExportChartsCommand, "dao", new=mocker.MagicMock())
    mocker.patch.object(
        ExportChartsCommand.dao,
        "find_by_ids",
        return_value=[accessible_chart, inaccessible_chart],
    )

    mock_sm = mocker.patch(
        "superset.commands.chart.export.security_manager",
    )
    mock_sm.can_access_chart.side_effect = [True, False]

    cmd = ExportChartsCommand([1, 2])
    with pytest.raises(ChartAccessDeniedError):
        cmd.validate()
