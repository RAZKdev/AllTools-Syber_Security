import os
import tempfile
from pathlib import Path
import pytest

from app.core.database_init import initialize_database
from app.dependencies import set_db_path

# Root-level session sandbox: guarantees that ALL test imports and executions
# are isolated to a temporary directory and NEVER touch %LOCALAPPDATA%\AllTools-CyberSec.
_global_test_temp = tempfile.TemporaryDirectory(prefix="alltools_cybersec_test_")
os.environ["ALLTOOLS_DATA_DIR"] = _global_test_temp.name


@pytest.fixture(autouse=True)
def isolated_test_database(tmp_path: Path, monkeypatch):
    """
    Ensure each individual test function executes against its own isolated temporary SQLite database.
    """
    db_file = tmp_path / "isolated_workbench.db"
    initialize_database(db_path=db_file)
    set_db_path(db_file)
    monkeypatch.setenv("ALLTOOLS_DATA_DIR", str(tmp_path))
    yield db_file
    set_db_path(None)
