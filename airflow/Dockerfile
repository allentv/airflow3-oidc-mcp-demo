# Minimal Airflow 3 with REST API v2 enabled (api-server runs via `standalone`).
# No extra providers needed: the demo DAG uses core decorators only.
FROM apache/airflow:3.4.0

# The base image runs as `airflow`; switch to root only for file setup.
USER root

# Writes demo API credentials to the simple-auth-manager passwords file, then
# runs scheduler + api-server + dag-processor + triggerer in one process.
COPY entrypoint.sh /usr/local/bin/demo-entrypoint.sh
RUN chmod +x /usr/local/bin/demo-entrypoint.sh

# Demo DAGs shipped with the repo (parsed by the dag-processor).
COPY --chown=airflow:airflow dags/ /opt/airflow/dags/

USER airflow
# Bypass the image's /entrypoint (it rewrites unknown commands as `airflow <cmd>`);
# demo-entrypoint.sh ends with `exec airflow standalone` itself.
ENTRYPOINT ["/usr/local/bin/demo-entrypoint.sh"]