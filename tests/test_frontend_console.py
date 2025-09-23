"""Execute Node-based unit tests for the frontend console module."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_frontend_console_module():
    """Run the Node test suite that validates the reusable console script."""

    test_script = Path(__file__).parent / "js" / "console.test.js"
    result = subprocess.run(
        ["node", str(test_script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        output = (result.stdout or "") + (result.stderr or "")
        raise AssertionError(f"Node console tests failed:\n{output}")

