from unittest.mock import Mock

import pytest


@pytest.fixture
def mock() -> Mock:
    return Mock()
