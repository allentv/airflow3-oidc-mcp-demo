"""Demo DAG: a small three-step report so MCP tools have runs and logs to read.

Uses `logging` (not `print`) — Airflow 3 writes logger records to the task log
files that the REST API serves; raw stdout is not captured. Core SDK imports
only: no extra providers required.
"""

from __future__ import annotations

import logging
from datetime import datetime

from airflow.sdk import dag, task

logger = logging.getLogger(__name__)


@dag(
    dag_id="demo_report",
    description="Three-step demo report for the MCP talk",
    schedule="@daily",
    start_date=datetime(2024, 1, 1),
    catchup=False,
    tags=["demo"],
)
def demo_report():
    @task
    def extract() -> list[int]:
        rows = [1, 2, 3, 4, 5]
        logger.info("extracted %d rows", len(rows))
        return rows

    @task
    def transform(rows: list[int]) -> dict:
        total = sum(rows)
        logger.info("transformed rows -> total=%d", total)
        return {"total": total, "row_count": len(rows)}

    @task
    def load(summary: dict) -> None:
        logger.info("loaded summary into report store: %s", summary)

    load(transform(extract()))


demo_report()