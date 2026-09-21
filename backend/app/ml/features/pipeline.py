"""
CloudShield IQ — Feature Engineering Pipeline
==============================================
Feature extractor and preprocessing pipeline transforming raw/canonical
cloud security telemetry into numerical feature matrices for ML anomaly detection.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math
from typing import Any, Sequence, Union

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import OneHotEncoder

from app.schemas.events import CloudSecurityEvent


def _parse_timestamp(val: Any) -> datetime:
    """Parse various timestamp representations into timezone-aware UTC datetime."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, str):
        try:
            cleaned = val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _is_private_ip(ip_str: Any) -> bool:
    """Determine whether an IP address is private/internal RFC1918."""
    if not ip_str or not isinstance(ip_str, str):
        return True  # Default to internal/neutral
    try:
        # Some synthetic logs have invalid octets like 192.168.0.219.92
        parts = ip_str.strip().split(".")
        if len(parts) >= 4:
            valid_ip = ".".join(parts[:4])
            ip_obj = ipaddress.ip_address(valid_ip)
            return ip_obj.is_private or ip_obj.is_loopback
        return False
    except ValueError:
        return False


class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Transforms CloudSecurityEvent models or tabular DataFrames into a dense,
    scaled numerical matrix suitable for Isolation Forest or other anomaly detectors.
    """

    CATEGORICAL_COLS = ["cloud_provider", "actor_type", "outcome", "action_norm", "resource_norm"]

    def __init__(self, max_categories: int = 30) -> None:
        self.max_categories = max_categories
        self.encoder = OneHotEncoder(
            sparse_output=False,
            handle_unknown="ignore",
            max_categories=max_categories,
        )
        self.feature_names_: list[str] = []
        self._is_fitted = False

    def _normalize_input(
        self, X: Union[pd.DataFrame, Sequence[CloudSecurityEvent], Sequence[dict[str, Any]]]
    ) -> pd.DataFrame:
        """Convert varied input formats into a standardized DataFrame."""
        if isinstance(X, pd.DataFrame):
            df = X.copy()
        elif isinstance(X, (list, tuple)) and len(X) > 0 and isinstance(X[0], CloudSecurityEvent):
            df = pd.DataFrame([
                {
                    "timestamp": e.timestamp,
                    "cloud_provider": e.cloud_provider.value if hasattr(e.cloud_provider, "value") else str(e.cloud_provider),
                    "resource_type": e.resource_type,
                    "action": getattr(e, "canonical_action", None)
                    or getattr(e, "raw_action", "Unknown"),
                    "actor_type": e.actor_type.value if hasattr(e.actor_type, "value") else str(e.actor_type),
                    "actor_name": e.actor_name,
                    "source_ip": e.source_ip,
                    "region": e.region or "global",
                    "mfa_used": bool(e.mfa_used),
                    "outcome": e.outcome.value if hasattr(e.outcome, "value") else str(e.outcome),
                    "session_duration_s": e.session_duration_s,
                }
                for e in X
            ])
        elif isinstance(X, (list, tuple)):
            df = pd.DataFrame(list(X))
        else:
            df = pd.DataFrame(X)

        if df.empty:
            return pd.DataFrame(columns=[
                "cloud_provider", "resource_type", "action", "actor_type",
                "actor_name", "source_ip", "region", "mfa_used", "outcome",
                "session_duration_s", "timestamp"
            ])

        # Standardize column mappings if needed
        if "canonical_action" in df.columns and "action" not in df.columns:
            df["action"] = df["canonical_action"]
        elif "raw_action" in df.columns and "action" not in df.columns:
            df["action"] = df["raw_action"]

        if "action" not in df.columns:
            df["action"] = "Unknown"
        if "resource_type" not in df.columns:
            df["resource_type"] = "Unknown"
        if "cloud_provider" not in df.columns:
            df["cloud_provider"] = "aws"
        if "actor_type" not in df.columns:
            df["actor_type"] = "user"
        if "outcome" not in df.columns:
            df["outcome"] = "Success"
        if "mfa_used" not in df.columns:
            df["mfa_used"] = False
        if "session_duration_s" not in df.columns:
            df["session_duration_s"] = 0.0

        return df

    def _extract_tabular_features(self, df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Extract explicit domain features and isolate categorical fields for encoding."""
        # 1. Temporal features
        timestamps = df["timestamp"].apply(_parse_timestamp) if "timestamp" in df.columns else pd.Series([datetime.now(timezone.utc)] * len(df))
        hours = timestamps.apply(lambda ts: ts.hour)
        days = timestamps.apply(lambda ts: ts.weekday())

        num_df = pd.DataFrame(index=df.index)
        num_df["hour_sin"] = hours.apply(lambda h: math.sin(2 * math.pi * h / 24.0))
        num_df["hour_cos"] = hours.apply(lambda h: math.cos(2 * math.pi * h / 24.0))
        num_df["is_weekend"] = days.apply(lambda d: 1.0 if d >= 5 else 0.0)
        num_df["is_off_hours"] = hours.apply(lambda h: 1.0 if (h < 7 or h > 19) else 0.0)

        # 2. MFA & Credential flags
        num_df["mfa_absent"] = df["mfa_used"].apply(lambda m: 0.0 if bool(m) else 1.0)

        actors = df["actor_type"].astype(str).str.lower()
        names = df["actor_name"].astype(str).str.lower() if "actor_name" in df.columns else pd.Series([""] * len(df))
        num_df["is_root_principal"] = [
            1.0 if ("root" in a or "root" in n) else 0.0
            for a, n in zip(actors, names)
        ]

        # 3. Outcome risk flag (failures, denials)
        outcomes = df["outcome"].astype(str).str.lower()
        num_df["is_denied_or_failure"] = outcomes.apply(
            lambda o: 1.0 if o in ("failure", "denied", "error", "failed") else 0.0
        )

        # 4. Session duration (log-scaled)
        durations = pd.to_numeric(df["session_duration_s"], errors="coerce").fillna(0.0)
        num_df["log_session_duration"] = np.log1p(np.maximum(0.0, durations))
        num_df["has_active_session"] = (durations > 0.0).astype(float)

        # 5. Network ingress / IP posture
        ips = df["source_ip"] if "source_ip" in df.columns else pd.Series([""] * len(df))
        num_df["is_private_ip"] = ips.apply(lambda ip: 1.0 if _is_private_ip(ip) else 0.0)
        num_df["is_public_ip"] = 1.0 - num_df["is_private_ip"]

        # 6. Categorical preparation
        cat_df = pd.DataFrame(index=df.index)
        cat_df["cloud_provider"] = df["cloud_provider"].astype(str).str.lower()
        cat_df["actor_type"] = df["actor_type"].astype(str).str.lower()
        cat_df["outcome"] = df["outcome"].astype(str).str.lower()
        cat_df["action_norm"] = df["action"].astype(str)
        cat_df["resource_norm"] = df["resource_type"].astype(str)

        return num_df, cat_df

    def fit(self, X: Union[pd.DataFrame, Sequence[Any]], y: Any = None) -> SecurityFeatureExtractor:
        """Fit categorical encoders and construct feature registry."""
        df = self._normalize_input(X)
        if df.empty:
            self._is_fitted = True
            return self

        num_df, cat_df = self._extract_tabular_features(df)
        self.encoder.fit(cat_df[self.CATEGORICAL_COLS])

        cat_feature_names = self.encoder.get_feature_names_out(self.CATEGORICAL_COLS).tolist()
        self.feature_names_ = list(num_df.columns) + cat_feature_names
        self._is_fitted = True
        return self

    def transform(self, X: Union[pd.DataFrame, Sequence[Any]]) -> np.ndarray:
        """Transform input events into a unified numerical feature matrix."""
        if not self._is_fitted:
            raise RuntimeError("SecurityFeatureExtractor must be fitted before transform().")

        df = self._normalize_input(X)
        if df.empty:
            return np.empty((0, len(self.feature_names_)), dtype=np.float64)

        num_df, cat_df = self._extract_tabular_features(df)
        encoded_cats = self.encoder.transform(cat_df[self.CATEGORICAL_COLS])
        combined = np.hstack([num_df.to_numpy(dtype=np.float64), encoded_cats])
        return combined

    def fit_transform(self, X: Union[pd.DataFrame, Sequence[Any]], y: Any = None) -> np.ndarray:
        """Fit and transform in one step."""
        return self.fit(X, y).transform(X)
