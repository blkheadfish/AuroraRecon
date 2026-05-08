"""
storage/minio_client.py —— MinIO 对象存储客户端

负责：
  - 渗透测试报告上传（Markdown / PDF）
  - 工具原始输出归档
  - 扫描结果文件管理
"""
from __future__ import annotations

import io
import logging
import os
from typing import Optional

from minio import Minio
from minio.error import S3Error

logger = logging.getLogger(__name__)

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

BUCKET_REPORTS = "pentest-reports"
BUCKET_ARTIFACTS = "pentest-artifacts"


class StorageClient:
    """MinIO 对象存储封装"""

    def __init__(self):
        self._client: Optional[Minio] = None

    def _get_client(self) -> Minio:
        if self._client is None:
            self._client = Minio(
                MINIO_ENDPOINT,
                access_key=MINIO_ACCESS_KEY,
                secret_key=MINIO_SECRET_KEY,
                secure=MINIO_SECURE,
            )
        return self._client
    
    def ensure_buckets(self) -> None:
        client = self._get_client()
        for bucket in [BUCKET_REPORTS, BUCKET_ARTIFACTS]:
            try:
                if not client.bucket_exists(bucket):
                    client.make_bucket(bucket)
                    logger.info(f"[MinIO] 创建 Bucket: {bucket}")
            except Exception:
                logger.info(f"bucket已存在")

    def upload_report(
        self,
        task_id: str,
        filename: str,
        content: str,
        content_type: str = "text/markdown",
    ) -> str:
        """
        上传报告文件到 MinIO

        Returns:
            对象路径（用于后续下载）
        """
        client = self._get_client()
        object_name = f"{task_id}/{filename}"

        data = content.encode("utf-8")
        client.put_object(
            BUCKET_REPORTS,
            object_name,
            io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )

        logger.info(f"[MinIO] 报告已上传: {BUCKET_REPORTS}/{object_name}")
        return f"{BUCKET_REPORTS}/{object_name}"

    def upload_artifact(
        self,
        task_id: str,
        tool_name: str,
        content: str,
        filename: Optional[str] = None,
    ) -> str:
        """
        上传工具输出/扫描产物

        Returns:
            对象路径
        """
        client = self._get_client()
        fname = filename or f"{tool_name}_output.txt"
        object_name = f"{task_id}/{tool_name}/{fname}"

        data = content.encode("utf-8")
        client.put_object(
            BUCKET_ARTIFACTS,
            object_name,
            io.BytesIO(data),
            length=len(data),
            content_type="text/plain",
        )

        return f"{BUCKET_ARTIFACTS}/{object_name}"

    def download_report(self, task_id: str, filename: str) -> Optional[str]:
        """下载报告内容"""
        client = self._get_client()
        object_name = f"{task_id}/{filename}"
        try:
            response = client.get_object(BUCKET_REPORTS, object_name)
            content = response.read().decode("utf-8")
            response.close()
            response.release_conn()
            return content
        except S3Error as e:
            logger.warning(f"[MinIO] 下载失败: {e}")
            return None

    def get_report_url(
        self, task_id: str, filename: str, expires_hours: int = 24
    ) -> Optional[str]:
        """生成报告的预签名下载 URL"""
        from datetime import timedelta

        client = self._get_client()
        object_name = f"{task_id}/{filename}"
        try:
            url = client.presigned_get_object(
                BUCKET_REPORTS,
                object_name,
                expires=timedelta(hours=expires_hours),
            )
            return url
        except S3Error as e:
            logger.warning(f"[MinIO] 生成下载链接失败: {e}")
            return None

    def list_task_files(self, task_id: str, bucket: str = BUCKET_REPORTS) -> list[str]:
        """列出某个任务的所有文件"""
        client = self._get_client()
        objects = client.list_objects(bucket, prefix=f"{task_id}/", recursive=True)
        return [obj.object_name for obj in objects]

    def delete_task_files(self, task_id: str) -> None:
        """删除某个任务的所有存储文件"""
        client = self._get_client()
        for bucket in [BUCKET_REPORTS, BUCKET_ARTIFACTS]:
            objects = client.list_objects(bucket, prefix=f"{task_id}/", recursive=True)
            for obj in objects:
                client.remove_object(bucket, obj.object_name)
        logger.info(f"[MinIO] 已删除任务文件: {task_id}")


_storage: Optional[StorageClient] = None


def get_storage() -> StorageClient:
    global _storage
    if _storage is None:
        _storage = StorageClient()
        try:
            _storage.ensure_buckets()
        except Exception as e:
            logger.warning(f"[MinIO] 初始化失败（将使用本地文件系统回退）: {e}")
    return _storage
