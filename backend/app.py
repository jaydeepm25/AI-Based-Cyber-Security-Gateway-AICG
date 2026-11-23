"""Compatibility launcher for the unified AEGIS-OT gateway API/HMI."""

import atexit
import sys
from pathlib import Path

# Ensure backend directory and repository root are on sys.path for direct launcher execution
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(1, str(PROJECT_ROOT))

from aegis_gateway.api import apply_proxy_fix, create_app
from aegis_gateway.runtime import GatewayRuntime

runtime = GatewayRuntime()
if runtime.settings.baseline_enabled:
    runtime.start_baseline()
    atexit.register(runtime.stop_baseline)
app = create_app(runtime)
apply_proxy_fix(app)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False, threaded=True)
