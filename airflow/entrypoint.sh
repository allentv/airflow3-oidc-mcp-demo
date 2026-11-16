#!/usr/bin/env bash
# Materialize demo API credentials, then hand off to `airflow standalone`
# (which runs db migrate + scheduler + api-server + dag-processor + triggerer).
#
# Passwords come from the environment (docker-compose.yml / .env) so no
# plaintext secret lives outside clearly-labelled demo defaults.
set -euo pipefail

python - <<'PY'
import json
import os

airflow_home = os.environ.get("AIRFLOW_HOME", "/opt/airflow")
users = {
    os.environ.get("AIRFLOW_READER_USERNAME", "mcp-reader"): os.environ["AIRFLOW_READER_PASSWORD"],
    os.environ.get("AIRFLOW_WRITER_USERNAME", "mcp-writer"): os.environ["AIRFLOW_WRITER_PASSWORD"],
}
path = os.path.join(airflow_home, "simple_auth_manager_passwords.json.generated")
with open(path, "w", encoding="utf-8") as fh:
    json.dump(users, fh)
print(f"demo: wrote simple-auth-manager passwords for {sorted(users)} -> {path}")
PY

exec airflow standalone