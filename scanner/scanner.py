"""
Docker Image Vulnerability Scanner Worker.

This module implements a worker service that polls an SQS queue for scan jobs,
executes vulnerability scans using Trivy, and stores results in PostgreSQL and S3.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generator, TypedDict

import boto3
import psycopg2
from botocore.exceptions import BotoCoreError, ClientError
from psycopg2.extensions import connection as PgConnection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Enumeration of possible scan job statuses."""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanType(Enum):
    """Enumeration of supported scan types."""

    DOCKER_IMAGE = "docker-image"


class ScannerError(Exception):
    """Base exception for scanner-related errors."""


class ConfigurationError(ScannerError):
    """Raised when required configuration is missing or invalid."""


class DatabaseError(ScannerError):
    """Raised when database operations fail."""


class ScanExecutionError(ScannerError):
    """Raised when the vulnerability scan fails."""


class VulnerabilitySummary(TypedDict):
    """Type definition for vulnerability summary statistics."""

    total: int
    critical: int
    high: int
    medium: int
    low: int


class ScanResult(TypedDict):
    """Type definition for scan results."""

    scan_results: dict[str, Any]
    vulnerabilities: list[dict[str, Any]]
    summary: VulnerabilitySummary


@dataclass(frozen=True)
class Config:
    """Application configuration loaded from environment variables.

    Attributes:
        sqs_queue_url: URL of the SQS queue to poll for scan jobs.
        s3_bucket: Name of the S3 bucket for storing scan results.
        db_host: PostgreSQL database host.
        db_name: PostgreSQL database name.
        db_user: PostgreSQL database user.
        db_password: PostgreSQL database password.
        scan_timeout: Maximum time in seconds for a single scan operation.
        poll_wait_seconds: SQS long polling wait time in seconds.
        visibility_timeout: SQS message visibility timeout in seconds.
    """

    sqs_queue_url: str
    s3_bucket: str
    db_host: str
    db_name: str
    db_user: str
    db_password: str
    scan_timeout: int = 600
    poll_wait_seconds: int = 20
    visibility_timeout: int = 300

    @classmethod
    def from_environment(cls) -> Config:
        """Create configuration from environment variables.

        Returns:
            Config instance populated from environment variables.

        Raises:
            ConfigurationError: If required environment variables are missing.
        """
        required_vars = {
            "SQS_QUEUE_URL": "sqs_queue_url",
            "S3_BUCKET": "s3_bucket",
            "DB_HOST": "db_host",
            "DB_NAME": "db_name",
            "DB_USER": "db_user",
            "DB_PASSWORD": "db_password",
        }

        missing_vars = [var for var in required_vars if not os.environ.get(var)]
        if missing_vars:
            raise ConfigurationError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        return cls(
            sqs_queue_url=os.environ["SQS_QUEUE_URL"],
            s3_bucket=os.environ["S3_BUCKET"],
            db_host=os.environ["DB_HOST"],
            db_name=os.environ["DB_NAME"],
            db_user=os.environ["DB_USER"],
            db_password=os.environ["DB_PASSWORD"],
            scan_timeout=int(os.environ.get("SCAN_TIMEOUT", "600")),
            poll_wait_seconds=int(os.environ.get("POLL_WAIT_SECONDS", "20")),
            visibility_timeout=int(os.environ.get("VISIBILITY_TIMEOUT", "300")),
        )


@dataclass
class ScanJob:
    """Represents a scan job from the SQS queue.

    Attributes:
        scan_id: Unique identifier for the scan job.
        scan_type: Type of scan to perform.
        target: Target to scan (e.g., Docker image name).
        receipt_handle: SQS message receipt handle for deletion.
    """

    scan_id: str
    scan_type: ScanType
    target: str
    receipt_handle: str

    @classmethod
    def from_sqs_message(cls, message: dict[str, Any]) -> ScanJob:
        """Create a ScanJob from an SQS message.

        Args:
            message: Raw SQS message dictionary.

        Returns:
            ScanJob instance.

        Raises:
            ValueError: If the message format is invalid or scan type is unsupported.
        """
        body = json.loads(message["Body"])

        try:
            scan_type = ScanType(body["type"])
        except ValueError as e:
            raise ValueError(f"Unsupported scan type: {body.get('type')}") from e

        return cls(
            scan_id=body["scan_id"],
            scan_type=scan_type,
            target=body["target"],
            receipt_handle=message["ReceiptHandle"],
        )


class DatabaseManager:
    """Manages PostgreSQL database connections and operations."""

    def __init__(self, config: Config) -> None:
        """Initialize the database manager.

        Args:
            config: Application configuration containing database credentials.
        """
        self._config = config

    @contextmanager
    def get_connection(self) -> Generator[PgConnection, None, None]:
        """Context manager for database connections.

        Yields:
            Active database connection.

        Raises:
            DatabaseError: If connection fails.
        """
        conn: PgConnection | None = None
        try:
            conn = psycopg2.connect(
                host=self._config.db_host,
                database=self._config.db_name,
                user=self._config.db_user,
                password=self._config.db_password,
                connect_timeout=10,
                sslmode="require",
            )
            yield conn
        except psycopg2.Error as e:
            raise DatabaseError(f"Database connection failed: {e}") from e
        finally:
            if conn is not None:
                conn.close()

    def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        error_message: str | None = None,
    ) -> None:
        """Update the status of a scan job in the database.

        Args:
            scan_id: Unique identifier of the scan job.
            status: New status to set.
            error_message: Optional error message for failed scans.

        Raises:
            DatabaseError: If the update operation fails.
        """
        queries = {
            ScanStatus.SCANNING: (
                "UPDATE scan_jobs SET status = %s, started_at = NOW() WHERE id = %s",
                (status.value, scan_id),
            ),
            ScanStatus.COMPLETED: (
                "UPDATE scan_jobs SET status = %s, completed_at = NOW() WHERE id = %s",
                (status.value, scan_id),
            ),
            ScanStatus.FAILED: (
                "UPDATE scan_jobs SET status = %s, completed_at = NOW(), "
                "error_message = %s WHERE id = %s",
                (status.value, error_message, scan_id),
            ),
        }

        if status not in queries:
            logger.warning("No query defined for status: %s", status)
            return

        query, params = queries[status]

        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, params)
                conn.commit()
            logger.info("Updated scan %s status to: %s", scan_id, status.value)
        except (psycopg2.Error, DatabaseError) as e:
            logger.error("Failed to update scan status: %s", e)
            raise DatabaseError(f"Failed to update scan status: {e}") from e

    def store_vulnerabilities(
        self,
        scan_id: str,
        vulnerabilities: list[dict[str, Any]],
    ) -> int:
        """Store discovered vulnerabilities in the database.

        Args:
            scan_id: Unique identifier of the scan job.
            vulnerabilities: List of vulnerability dictionaries from Trivy.

        Returns:
            Number of vulnerabilities stored.

        Raises:
            DatabaseError: If the storage operation fails.
        """
        if not vulnerabilities:
            logger.info("No vulnerabilities to store for scan %s", scan_id)
            return 0

        query = """
            INSERT INTO vulnerabilities
            (scan_job_id, cve_id, severity, package_name, installed_version,
             fixed_version, title, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    for vuln in vulnerabilities:
                        cursor.execute(
                            query,
                            (
                                scan_id,
                                vuln.get("VulnerabilityID"),
                                vuln.get("Severity"),
                                vuln.get("PkgName"),
                                vuln.get("InstalledVersion"),
                                vuln.get("FixedVersion"),
                                vuln.get("Title"),
                                vuln.get("Description"),
                            ),
                        )
                conn.commit()

            logger.info(
                "Stored %d vulnerabilities for scan %s",
                len(vulnerabilities),
                scan_id,
            )
            return len(vulnerabilities)

        except (psycopg2.Error, DatabaseError) as e:
            logger.error("Failed to store vulnerabilities: %s", e)
            raise DatabaseError(f"Failed to store vulnerabilities: {e}") from e


class VulnerabilityScanner:
    """Executes vulnerability scans using Trivy."""

    def __init__(self, timeout: int = 600) -> None:
        """Initialize the scanner.

        Args:
            timeout: Maximum time in seconds for a scan operation.
        """
        self._timeout = timeout

    def scan_docker_image(self, image_name: str) -> ScanResult:
        """Run a Trivy vulnerability scan on a Docker image.

        Args:
            image_name: Name/tag of the Docker image to scan.

        Returns:
            ScanResult containing full results, vulnerabilities list, and summary.

        Raises:
            ScanExecutionError: If the scan fails.
        """
        logger.info("Scanning Docker image: %s", image_name)

        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image_name],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )

            if result.returncode != 0:
                raise ScanExecutionError(f"Trivy scan failed: {result.stderr}")

            scan_results = json.loads(result.stdout)
            vulnerabilities = self._extract_vulnerabilities(scan_results)
            summary = self._calculate_summary(vulnerabilities)

            logger.info("Found %d vulnerabilities in %s", len(vulnerabilities), image_name)

            return ScanResult(
                scan_results=scan_results,
                vulnerabilities=vulnerabilities,
                summary=summary,
            )

        except subprocess.TimeoutExpired as e:
            raise ScanExecutionError(
                f"Scan timed out after {self._timeout} seconds"
            ) from e
        except json.JSONDecodeError as e:
            raise ScanExecutionError(f"Failed to parse scan results: {e}") from e

    @staticmethod
    def _extract_vulnerabilities(
        scan_results: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Extract vulnerabilities from Trivy scan results.

        Args:
            scan_results: Raw Trivy JSON output.

        Returns:
            Flattened list of all vulnerabilities.
        """
        vulnerabilities: list[dict[str, Any]] = []

        for result in scan_results.get("Results", []):
            vulns = result.get("Vulnerabilities")
            if vulns:
                vulnerabilities.extend(vulns)

        return vulnerabilities

    @staticmethod
    def _calculate_summary(
        vulnerabilities: list[dict[str, Any]],
    ) -> VulnerabilitySummary:
        """Calculate vulnerability counts by severity.

        Args:
            vulnerabilities: List of vulnerability dictionaries.

        Returns:
            Summary with counts for each severity level.
        """
        return VulnerabilitySummary(
            total=len(vulnerabilities),
            critical=sum(1 for v in vulnerabilities if v.get("Severity") == "CRITICAL"),
            high=sum(1 for v in vulnerabilities if v.get("Severity") == "HIGH"),
            medium=sum(1 for v in vulnerabilities if v.get("Severity") == "MEDIUM"),
            low=sum(1 for v in vulnerabilities if v.get("Severity") == "LOW"),
        )


class ScanWorker:
    """Main worker class that orchestrates the scan workflow."""

    def __init__(self, config: Config) -> None:
        """Initialize the scan worker.

        Args:
            config: Application configuration.
        """
        self._config = config
        self._sqs = boto3.client("sqs")
        self._s3 = boto3.client("s3")
        self._db = DatabaseManager(config)
        self._scanner = VulnerabilityScanner(timeout=config.scan_timeout)

    def run(self) -> None:
        """Start the main worker loop.

        Continuously polls SQS for messages and processes scan jobs.
        Handles graceful shutdown on keyboard interrupt.
        """
        logger.info("Scanner worker starting...")
        logger.info("Queue URL: %s", self._config.sqs_queue_url)
        logger.info("S3 Bucket: %s", self._config.s3_bucket)
        logger.info("Database: %s", self._config.db_host)
        logger.info("Polling for messages...")

        while True:
            try:
                self._poll_and_process()
            except KeyboardInterrupt:
                logger.info("Received shutdown signal, exiting gracefully...")
                break
            except (BotoCoreError, ClientError) as e:
                logger.error("AWS service error: %s", e)
                time.sleep(10)
            except Exception as e:
                logger.exception("Unexpected worker error: %s", e)
                time.sleep(10)

    def _poll_and_process(self) -> None:
        """Poll SQS for messages and process any received."""
        response = self._sqs.receive_message(
            QueueUrl=self._config.sqs_queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=self._config.poll_wait_seconds,
            VisibilityTimeout=self._config.visibility_timeout,
        )

        messages = response.get("Messages", [])
        if not messages:
            logger.debug("No messages received, continuing to poll...")
            return

        for message in messages:
            self._process_message(message)

    def _process_message(self, message: dict[str, Any]) -> None:
        """Process a single scan job message.

        Args:
            message: Raw SQS message dictionary.
        """
        scan_job: ScanJob | None = None

        try:
            scan_job = ScanJob.from_sqs_message(message)

            logger.info("=" * 60)
            logger.info("Processing scan: %s", scan_job.scan_id)
            logger.info("Type: %s", scan_job.scan_type.value)
            logger.info("Target: %s", scan_job.target)
            logger.info("=" * 60)

            self._db.update_scan_status(scan_job.scan_id, ScanStatus.SCANNING)

            results = self._execute_scan(scan_job)
            self._upload_results(scan_job.scan_id, results)

            if results["vulnerabilities"]:
                self._db.store_vulnerabilities(
                    scan_job.scan_id,
                    results["vulnerabilities"],
                )

            self._db.update_scan_status(scan_job.scan_id, ScanStatus.COMPLETED)
            self._delete_message(scan_job.receipt_handle)

            logger.info("Scan completed successfully!")
            logger.info("Summary: %s", results["summary"])

        except Exception as e:
            logger.error("Error processing message: %s", e)
            if scan_job is not None:
                self._handle_scan_failure(scan_job.scan_id, str(e))

    def _execute_scan(self, scan_job: ScanJob) -> ScanResult:
        """Execute the appropriate scan based on scan type.

        Args:
            scan_job: The scan job to execute.

        Returns:
            Scan results.

        Raises:
            ScanExecutionError: If the scan fails.
        """
        if scan_job.scan_type == ScanType.DOCKER_IMAGE:
            return self._scanner.scan_docker_image(scan_job.target)

        raise ScanExecutionError(f"Unsupported scan type: {scan_job.scan_type}")

    def _upload_results(self, scan_id: str, results: ScanResult) -> None:
        """Upload scan results to S3.

        Args:
            scan_id: Unique identifier of the scan job.
            results: Scan results to upload.
        """
        s3_key = f"scans/{scan_id}/results.json"

        self._s3.put_object(
            Bucket=self._config.s3_bucket,
            Key=s3_key,
            Body=json.dumps(results["scan_results"], indent=2),
            ContentType="application/json",
        )

        logger.info("Uploaded results to S3: %s", s3_key)

    def _delete_message(self, receipt_handle: str) -> None:
        """Delete a processed message from SQS.

        Args:
            receipt_handle: SQS message receipt handle.
        """
        self._sqs.delete_message(
            QueueUrl=self._config.sqs_queue_url,
            ReceiptHandle=receipt_handle,
        )
        logger.debug("Deleted message from SQS")

    def _handle_scan_failure(self, scan_id: str, error_message: str) -> None:
        """Handle a failed scan by updating its status.

        Args:
            scan_id: Unique identifier of the failed scan job.
            error_message: Description of the failure.
        """
        try:
            self._db.update_scan_status(
                scan_id,
                ScanStatus.FAILED,
                error_message=error_message,
            )
        except DatabaseError:
            logger.exception("Failed to update scan status after failure")


def main() -> None:
    """Application entry point."""
    try:
        config = Config.from_environment()
        worker = ScanWorker(config)
        worker.run()
    except ConfigurationError as e:
        logger.critical("Configuration error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.critical("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
