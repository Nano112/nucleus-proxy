"""
Async Nucleus → S3 export service.

Streams file bytes from a Nucleus download URL directly into an S3
multipart upload so the proxy acts as a pipe — no temp files on disk.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

import aiohttp
import boto3
from botocore.config import Config as BotoConfig

logger = logging.getLogger(__name__)

PART_SIZE = 8 * 1024 * 1024  # 8 MB multipart parts
JOB_TTL_SECONDS = 3600  # auto-cleanup completed jobs after 1 h


class ExportStatus(str, Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    UPLOADING = "uploading"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class S3Config:
    bucket: str
    key: str
    region: str
    access_key: str
    secret_key: str
    endpoint: Optional[str] = None
    use_path_style: bool = False


@dataclass
class ExportJob:
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    nucleus_path: str = ""
    s3_config: Optional[S3Config] = None
    status: ExportStatus = ExportStatus.PENDING
    progress_bytes: int = 0
    total_bytes: int = 0
    error: Optional[str] = None
    created_at: float = field(default_factory=time.monotonic)
    completed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "nucleus_path": self.nucleus_path,
            "status": self.status.value,
            "progress_bytes": self.progress_bytes,
            "total_bytes": self.total_bytes,
            "error": self.error,
        }


class S3ExportManager:
    """Singleton that owns running export jobs."""

    _instance: Optional["S3ExportManager"] = None

    def __new__(cls) -> "S3ExportManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._jobs: Dict[str, ExportJob] = {}
        return cls._instance

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_job(self, nucleus_path: str, s3_config: S3Config) -> ExportJob:
        self._cleanup_old_jobs()
        job = ExportJob(nucleus_path=nucleus_path, s3_config=s3_config)
        self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[ExportJob]:
        return self._jobs.get(job_id)

    async def execute_export(self, job: ExportJob, download_url: str) -> None:
        """Stream bytes from *download_url* into S3 via multipart upload."""
        cfg = job.s3_config
        loop = asyncio.get_running_loop()
        upload_id: Optional[str] = None

        s3_kwargs: dict = {
            "region_name": cfg.region,
            "aws_access_key_id": cfg.access_key,
            "aws_secret_access_key": cfg.secret_key,
        }
        if cfg.endpoint:
            s3_kwargs["endpoint_url"] = cfg.endpoint
        if cfg.use_path_style:
            s3_kwargs["config"] = BotoConfig(s3={"addressing_style": "path"})

        s3 = boto3.client("s3", **s3_kwargs)

        try:
            job.status = ExportStatus.DOWNLOADING

            async with aiohttp.ClientSession() as session:
                async with session.get(download_url) as resp:
                    if resp.status != 200:
                        raise RuntimeError(
                            f"Nucleus download failed: {resp.status} {await resp.text()}"
                        )

                    job.total_bytes = int(resp.headers.get("Content-Length", 0))
                    job.status = ExportStatus.UPLOADING

                    # Start multipart upload (sync boto3 in executor)
                    mpu = await loop.run_in_executor(
                        None,
                        lambda: s3.create_multipart_upload(
                            Bucket=cfg.bucket, Key=cfg.key
                        ),
                    )
                    upload_id = mpu["UploadId"]
                    parts: list = []
                    part_number = 1
                    buf = bytearray()

                    async for chunk in resp.content.iter_any():
                        buf.extend(chunk)
                        job.progress_bytes += len(chunk)

                        while len(buf) >= PART_SIZE:
                            part_data = bytes(buf[:PART_SIZE])
                            del buf[:PART_SIZE]

                            part_resp = await loop.run_in_executor(
                                None,
                                lambda pd=part_data, pn=part_number: s3.upload_part(
                                    Bucket=cfg.bucket,
                                    Key=cfg.key,
                                    UploadId=upload_id,
                                    PartNumber=pn,
                                    Body=pd,
                                ),
                            )
                            parts.append(
                                {"ETag": part_resp["ETag"], "PartNumber": part_number}
                            )
                            part_number += 1

                    # Flush remaining buffer
                    if buf:
                        part_resp = await loop.run_in_executor(
                            None,
                            lambda: s3.upload_part(
                                Bucket=cfg.bucket,
                                Key=cfg.key,
                                UploadId=upload_id,
                                PartNumber=part_number,
                                Body=bytes(buf),
                            ),
                        )
                        parts.append(
                            {"ETag": part_resp["ETag"], "PartNumber": part_number}
                        )

            # Complete multipart upload
            await loop.run_in_executor(
                None,
                lambda: s3.complete_multipart_upload(
                    Bucket=cfg.bucket,
                    Key=cfg.key,
                    UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                ),
            )

            job.status = ExportStatus.COMPLETED
            job.completed_at = time.monotonic()
            logger.info(
                "Export completed: %s → s3://%s/%s (%d bytes)",
                job.nucleus_path,
                cfg.bucket,
                cfg.key,
                job.progress_bytes,
            )

        except Exception as exc:
            job.status = ExportStatus.FAILED
            job.error = str(exc)
            job.completed_at = time.monotonic()
            logger.error("Export failed for %s: %s", job.nucleus_path, exc)

            # Abort multipart upload on failure
            if upload_id:
                try:
                    await loop.run_in_executor(
                        None,
                        lambda: s3.abort_multipart_upload(
                            Bucket=cfg.bucket,
                            Key=cfg.key,
                            UploadId=upload_id,
                        ),
                    )
                except Exception:
                    logger.warning("Failed to abort multipart upload %s", upload_id)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def _cleanup_old_jobs(self) -> None:
        now = time.monotonic()
        expired = [
            jid
            for jid, job in self._jobs.items()
            if job.completed_at and (now - job.completed_at) > JOB_TTL_SECONDS
        ]
        for jid in expired:
            del self._jobs[jid]
