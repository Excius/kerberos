"""Configuration values for the project.

This module requires sensitive values to be provided via environment
variables. It will optionally load a local `.env` file (development only) if
python-dotenv is installed, but it will raise a RuntimeError at import time if
the required secret environment variables are not set. This ensures we don't
keep secrets in the source tree or rely on hard-coded fallbacks.
"""

import os
from pathlib import Path

try:
	# Load .env from project root when available (development convenience)
	from dotenv import load_dotenv

	env_path = Path(__file__).resolve().parents[1] / ".env"
	load_dotenv(dotenv_path=env_path)
except Exception:
	# If python-dotenv isn't installed or load fails, continue and rely on
	# environment variables being set by the runtime environment.
	pass


def _require_env_bytes(name: str) -> bytes:
	"""Return the environment variable as bytes or raise if unset."""
	v = os.environ.get(name)
	if v is None:
		raise RuntimeError(
			f"Required environment variable '{name}' is not set. "
			"Set it in the environment or provide a .env file for development."
		)
	return v.encode()


# Required secrets (must be present in environment or .env during development)
TGS_SECRET_KEY = _require_env_bytes("TGS_SECRET_KEY")
CA_PASSWORD = _require_env_bytes("CA_PASSWORD")


# Non-sensitive configuration with sensible defaults
CA_PORT = int(os.environ.get("CA_PORT", "5000"))

PROVISIONING_SERVER_PORT = int(os.environ.get("PROVISIONING_SERVER_PORT", "5001"))
PROVISIONING_SERVER_URL = os.environ.get("PROVISIONING_SERVER_URL", "http://localhost:5001")

YOUR_REALM = os.environ.get("YOUR_REALM", "MYKERBEROSPROJECT")