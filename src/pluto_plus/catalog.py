"""Small durable catalog for captures, analyses, and operation receipts."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from pluto_plus.models import (
    AnalysisResult,
    ArtifactSummary,
    JobState,
    ScanJob,
    ScanResult,
    StreamJob,
    utc_now,
)


class Catalog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL,
                    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
                );
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS stream_jobs (
                    job_id TEXT PRIMARY KEY,
                    radio_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS stream_jobs_radio_created
                    ON stream_jobs(radio_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    radio_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS scan_jobs_radio_created
                    ON scan_jobs(radio_id, created_at DESC);
                """
            )

    def put_artifact(self, artifact: ArtifactSummary) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?)",
                (artifact.artifact_id, artifact.created_at.isoformat(), artifact.model_dump_json()),
            )

    def list_artifacts(self) -> list[ArtifactSummary]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT document FROM artifacts ORDER BY created_at DESC, artifact_id DESC"
            ).fetchall()
        return [ArtifactSummary.model_validate_json(row[0]) for row in rows]

    def get_artifact(self, artifact_id: str) -> ArtifactSummary | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        return None if row is None else ArtifactSummary.model_validate_json(row[0])

    def put_analysis(self, analysis: AnalysisResult) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO analyses VALUES (?, ?, ?, ?)",
                (
                    analysis.analysis_id,
                    analysis.artifact_id,
                    analysis.created_at.isoformat(),
                    analysis.model_dump_json(),
                ),
            )

    def list_analyses(self, artifact_id: str | None = None) -> list[AnalysisResult]:
        sql = "SELECT document FROM analyses"
        parameters: tuple[str, ...] = ()
        if artifact_id is not None:
            sql += " WHERE artifact_id = ?"
            parameters = (artifact_id,)
        sql += " ORDER BY created_at DESC, analysis_id DESC"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [AnalysisResult.model_validate_json(row[0]) for row in rows]

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        return None if row is None else AnalysisResult.model_validate_json(row[0])

    def put_scan(self, scan: ScanResult) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO scans VALUES (?, ?, ?)",
                (scan.scan_id, scan.created_at.isoformat(), scan.model_dump_json()),
            )

    def list_scans(self) -> list[ScanResult]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT document FROM scans ORDER BY created_at DESC, scan_id DESC"
            ).fetchall()
        return [ScanResult.model_validate_json(row[0]) for row in rows]

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return None if row is None else ScanResult.model_validate_json(row[0])

    def put_stream_job(self, job: StreamJob) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO stream_jobs VALUES (?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    radio_id = excluded.radio_id,
                    created_at = excluded.created_at,
                    document = excluded.document
                """,
                (
                    job.job_id,
                    job.radio_id,
                    job.created_at.isoformat(),
                    job.model_dump_json(),
                ),
            )

    def list_stream_jobs(self, radio_id: str | None = None) -> list[StreamJob]:
        sql = "SELECT document FROM stream_jobs"
        parameters: tuple[str, ...] = ()
        if radio_id is not None:
            sql += " WHERE radio_id = ?"
            parameters = (radio_id,)
        sql += " ORDER BY created_at DESC, job_id DESC"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [StreamJob.model_validate_json(row[0]) for row in rows]

    def get_stream_job(self, job_id: str) -> StreamJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM stream_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return None if row is None else StreamJob.model_validate_json(row[0])

    def put_scan_job(self, job: ScanJob) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_jobs VALUES (?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    radio_id = excluded.radio_id,
                    created_at = excluded.created_at,
                    document = excluded.document
                """,
                (
                    job.job_id,
                    job.radio_id,
                    job.created_at.isoformat(),
                    job.model_dump_json(),
                ),
            )

    def list_scan_jobs(self, radio_id: str | None = None) -> list[ScanJob]:
        sql = "SELECT document FROM scan_jobs"
        parameters: tuple[str, ...] = ()
        if radio_id is not None:
            sql += " WHERE radio_id = ?"
            parameters = (radio_id,)
        sql += " ORDER BY created_at DESC, job_id DESC"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [ScanJob.model_validate_json(row[0]) for row in rows]

    def get_scan_job(self, job_id: str) -> ScanJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM scan_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return None if row is None else ScanJob.model_validate_json(row[0])

    def recover_interrupted_jobs(self) -> None:
        """Make a prior daemon's non-terminal jobs observably terminal at startup."""

        finished_at = utc_now()
        reason = "Interrupted: daemon restarted before job completion"
        with self._connect() as connection:
            for table, model in (
                ("stream_jobs", StreamJob),
                ("scan_jobs", ScanJob),
            ):
                rows = connection.execute(
                    f"SELECT job_id, document FROM {table}"  # noqa: S608
                ).fetchall()
                for job_id, document in rows:
                    job = model.model_validate_json(document)
                    if job.state not in (JobState.PENDING, JobState.RUNNING):
                        continue
                    recovered = job.model_copy(
                        update={
                            "state": JobState.FAILED,
                            "finished_at": finished_at,
                            "error": reason,
                        }
                    )
                    connection.execute(
                        f"UPDATE {table} SET document = ? WHERE job_id = ?",  # noqa: S608
                        (recovered.model_dump_json(), job_id),
                    )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection
