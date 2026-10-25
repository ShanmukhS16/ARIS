"""ARIS configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "ARIS_DATABASE_URL", "sqlite+aiosqlite:///./aris.db"
        )
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ARIS_ANTHROPIC_API_KEY", "")
    )
    anthropic_model: str = field(
        default_factory=lambda: os.getenv("ARIS_ANTHROPIC_MODEL", "claude-sonnet-4-6")
    )
    ml_anomaly_threshold: float = field(
        default_factory=lambda: float(os.getenv("ARIS_ML_ANOMALY_THRESHOLD", "0.5"))
    )
    base_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent
    )


settings = Settings()
