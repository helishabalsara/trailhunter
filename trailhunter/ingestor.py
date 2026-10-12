"""
CloudTrail log ingestion — S3, live CloudTrail API, or local JSON files.
"""

import json
import gzip
import io
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Generator

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


class CloudTrailIngestor:
    def __init__(self, config: dict):
        self.config = config
        session_kwargs = {}
        aws_cfg = config.get("aws", {})
        if aws_cfg.get("access_key_id"):
            session_kwargs["aws_access_key_id"] = aws_cfg["access_key_id"]
            session_kwargs["aws_secret_access_key"] = aws_cfg["secret_access_key"]
        session_kwargs["region_name"] = aws_cfg.get("region", "us-east-1")
        self.session = boto3.Session(**session_kwargs)

    def ingest_from_s3(self) -> Generator[dict, None, None]:
        """Yield raw CloudTrail events from an S3 bucket."""
        s3 = self.session.client("s3")
        bucket = self.config["cloudtrail"]["bucket"]
        prefix = self.config["cloudtrail"].get("prefix", "")
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json.gz") and not key.endswith(".json"):
                    continue
                logger.debug(f"Reading s3://{bucket}/{key}")
                try:
                    response = s3.get_object(Bucket=bucket, Key=key)
                    body = response["Body"].read()
                    if key.endswith(".gz"):
                        body = gzip.decompress(body)
                    data = json.loads(body)
                    for event in data.get("Records", []):
                        yield event
                except (ClientError, BotoCoreError, json.JSONDecodeError) as e:
                    logger.warning(f"Failed to read {key}: {e}")

    def ingest_from_api(self) -> Generator[dict, None, None]:
        """Yield events from the CloudTrail LookupEvents API."""
        ct = self.session.client("cloudtrail")
        max_results = self.config["cloudtrail"].get("max_results", 1000)
        lookback_hours = self.config["cloudtrail"].get("lookback_hours", 24)
        start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        kwargs = {
            "StartTime": start_time,
            "MaxResults": min(max_results, 50),  # API max per page is 50
        }
        fetched = 0
        while fetched < max_results:
            try:
                response = ct.lookup_events(**kwargs)
            except (ClientError, BotoCoreError) as e:
                logger.error(f"CloudTrail API error: {e}")
                break
            for event in response.get("Events", []):
                raw = event.get("CloudTrailEvent")
                if raw:
                    try:
                        yield json.loads(raw)
                        fetched += 1
                    except json.JSONDecodeError:
                        continue
            next_token = response.get("NextToken")
            if not next_token or fetched >= max_results:
                break
            kwargs["NextToken"] = next_token

    def ingest_from_local(self, path: str) -> Generator[dict, None, None]:
        """Yield events from local JSON / JSON.GZ log files."""
        if os.path.isfile(path):
            files = [path]
        else:
            files = [
                os.path.join(root, f)
                for root, _, fnames in os.walk(path)
                for f in fnames
                if f.endswith(".json") or f.endswith(".json.gz")
            ]
        for filepath in files:
            logger.debug(f"Reading {filepath}")
            try:
                with open(filepath, "rb") as fh:
                    raw = fh.read()
                if filepath.endswith(".gz"):
                    raw = gzip.decompress(raw)
                data = json.loads(raw)
                for event in data.get("Records", [data]):
                    yield event
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read {filepath}: {e}")
