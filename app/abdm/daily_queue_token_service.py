"""Hospital-grade Daily Sequential Token Queue Manager for ABDM Scan & Share.

Tracks daily sequential queue token numbers per date, HIP facility, doctor (HPR ID), and counter ID.
Daily token sequence automatically resets to 1 each day.
"""
import json
import os
import threading
from datetime import datetime, timezone
from typing import Dict, Any

from app.logging.logger import get_logger

logger = get_logger(__name__)

STORAGE_PATH = os.path.join(os.getcwd(), "daily_tokens.json")


class HospitalDailyQueueTokenService:
    """Manages daily sequential queue tokens per date, facility, doctor, and counter."""

    def __init__(self, storage_path: str = STORAGE_PATH) -> None:
        self._storage_path = storage_path
        self._lock = threading.Lock()
        self._state: Dict[str, Any] = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if os.path.exists(self._storage_path):
            try:
                with open(self._storage_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load daily token state file, starting clean", error=str(e))
        return {}

    def _save_state(self) -> None:
        try:
            with open(self._storage_path, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            logger.error("Failed to persist daily token state file", error=str(e))

    def generate_next_token(
        self,
        *,
        hip_id: str = "IN2910002345",
        counter_id: str = "1",
        doctor_id: str | None = None,
    ) -> str:
        """Atomically generates the next daily sequential token number for the given date, doctor, and counter.
        Format: String integer ('1', '2', '3', '4'...)
        """
        with self._lock:
            today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            clean_hip = str(hip_id or "IN2910002345").strip()
            clean_counter = str(counter_id or "1").strip()
            clean_doctor = str(doctor_id or "").strip() or "default"

            key = f"{today_date}:{clean_hip}:{clean_doctor}:{clean_counter}"
            current_seq = self._state.get(key, 0)
            next_seq = current_seq + 1
            self._state[key] = next_seq
            self._save_state()

            logger.info(
                "Generated next daily hospital queue token",
                date=today_date,
                hip_id=clean_hip,
                counter_id=clean_counter,
                doctor_id=clean_doctor,
                token_number=str(next_seq),
            )
            return str(next_seq)

    def get_daily_tokens(
        self,
        *,
        date_str: str | None = None,
        hip_id: str | None = None,
        counter_id: str | None = None,
    ) -> Dict[str, Any]:
        """Fetch and return active daily tokens state filtered by date, HIP ID, or counter ID."""
        with self._lock:
            target_date = (date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")).strip()
            results = []
            for key, val in self._state.items():
                parts = key.split(":")
                if len(parts) >= 4:
                    rec_date, rec_hip, rec_doc, rec_counter = parts[0], parts[1], parts[2], parts[3]
                    if rec_date != target_date:
                        continue
                    if hip_id and rec_hip != str(hip_id).strip():
                        continue
                    if counter_id and rec_counter != str(counter_id).strip():
                        continue
                    results.append({
                        "key": key,
                        "date": rec_date,
                        "hipId": rec_hip,
                        "doctorId": rec_doc,
                        "counterId": rec_counter,
                        "lastTokenNumber": val,
                    })
            return {
                "status": "ok",
                "date": target_date,
                "totalRecords": len(results),
                "tokens": results,
            }


daily_queue_token_service = HospitalDailyQueueTokenService()

