"""Configuration management for production sensor forwarder."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ProductionConfig:
    """Configuration for the sensor forwarder."""
    
    sensor_id: str
    ingest_url: str
    api_token: str
    cowrie_log_path: str
    spool_path: str
    forwarder_timeout_seconds: int = 30
    forwarder_batch_size: int = 100
    forwarder_poll_seconds: int = 5
    
    @classmethod
    def from_env(cls, config_file: Optional[str] = None) -> "ProductionConfig":
        """
        Load configuration from environment variables or JSON config file.
        
        Environment variables:
        - SENSOR_ID: Unique identifier for this sensor (e.g., pi5-cowrie-01)
        - INGEST_URL: Target GCP ingest_api endpoint (e.g., http://34.124.181.196:8080/events)
        - HONEYPOT_API_TOKEN: Bearer token for authentication
        - COWRIE_LOG_PATH: Path to Cowrie JSON log file
        - FORWARDER_SPOOL_PATH: Path for local disk spool queue
        - FORWARDER_TIMEOUT_SECONDS: HTTP request timeout (default: 30)
        - FORWARDER_BATCH_SIZE: Max events per HTTP POST (default: 100)
        - FORWARDER_POLL_SECONDS: Polling interval in tail-mode (default: 5)
        
        Args:
            config_file: Optional path to JSON config file (overrides env vars if provided)
        
        Returns:
            ProductionConfig instance
        
        Raises:
            ValueError: If required fields are missing
        """
        if config_file:
            with open(config_file, "r") as f:
                data = json.load(f)
        else:
            data = {}
        
        # Environment variables take precedence
        sensor_id = os.getenv("SENSOR_ID") or data.get("sensor_id")
        ingest_url = os.getenv("INGEST_URL") or data.get("ingest_url")
        api_token = os.getenv("HONEYPOT_API_TOKEN") or data.get("api_token")
        cowrie_log_path = os.getenv("COWRIE_LOG_PATH") or data.get("cowrie_log_path")
        spool_path = os.getenv("FORWARDER_SPOOL_PATH") or data.get("spool_path")
        
        # Optional fields with defaults
        timeout = int(os.getenv("FORWARDER_TIMEOUT_SECONDS", data.get("forwarder_timeout_seconds", 30)))
        batch_size = int(os.getenv("FORWARDER_BATCH_SIZE", data.get("forwarder_batch_size", 100)))
        poll_seconds = int(os.getenv("FORWARDER_POLL_SECONDS", data.get("forwarder_poll_seconds", 5)))
        
        # Validate required fields
        missing = []
        if not sensor_id:
            missing.append("SENSOR_ID")
        if not ingest_url:
            missing.append("INGEST_URL")
        if not api_token:
            missing.append("HONEYPOT_API_TOKEN")
        if not cowrie_log_path:
            missing.append("COWRIE_LOG_PATH")
        if not spool_path:
            missing.append("FORWARDER_SPOOL_PATH")
        
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
        
        return cls(
            sensor_id=sensor_id,
            ingest_url=ingest_url,
            api_token=api_token,
            cowrie_log_path=cowrie_log_path,
            spool_path=spool_path,
            forwarder_timeout_seconds=timeout,
            forwarder_batch_size=batch_size,
            forwarder_poll_seconds=poll_seconds,
        )
    
    def to_dict(self) -> dict:
        """Convert config to dictionary (without sensitive token)."""
        return {
            "sensor_id": self.sensor_id,
            "ingest_url": self.ingest_url,
            "cowrie_log_path": self.cowrie_log_path,
            "spool_path": self.spool_path,
            "forwarder_timeout_seconds": self.forwarder_timeout_seconds,
            "forwarder_batch_size": self.forwarder_batch_size,
            "forwarder_poll_seconds": self.forwarder_poll_seconds,
        }
