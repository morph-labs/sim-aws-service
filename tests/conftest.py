from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sim_aws_service.main import create_app


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    os.environ["SIM_AWS_DB_URL"] = f"sqlite:///{tmp_path}/test.db"
    os.environ["SIM_AWS_SERVICE_MORPH_API_KEY"] = "svc_key_test"
    os.environ.pop("SERVICES_API_KEY", None)
    app = create_app()
    return TestClient(app)
