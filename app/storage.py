import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

STORAGE_DIR = Path("data")
STORAGE_FILE = STORAGE_DIR / "pac_files.json"
ACCESS_LOG_DIR = Path("logs")

def ensure_storage():
    STORAGE_DIR.mkdir(exist_ok=True)
    ACCESS_LOG_DIR.mkdir(exist_ok=True)
    if not STORAGE_FILE.exists():
        STORAGE_FILE.write_text("{}")

def load_pac_files() -> Dict[str, Any]:
    ensure_storage()
    return json.loads(STORAGE_FILE.read_text())

def save_pac_files(data: Dict[str, Any]):
    ensure_storage()
    STORAGE_FILE.write_text(json.dumps(data, indent=2))

def get_pac_file(pac_id: str) -> Dict[str, Any]:
    pac_files = load_pac_files()
    return pac_files.get(pac_id)

def save_pac_file(pac_id: str, pac_data: Dict[str, Any]):
    pac_files = load_pac_files()
    pac_files[pac_id] = pac_data
    save_pac_files(pac_files)

def delete_pac_file(pac_id: str):
    pac_files = load_pac_files()
    if pac_id in pac_files:
        del pac_files[pac_id]
        save_pac_files(pac_files)

def log_access(pac_id: str, client_ip: str):
    log_file = ACCESS_LOG_DIR / f"{pac_id}.log"
    timestamp = datetime.now().isoformat()
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {client_ip}\n")

def get_access_log(pac_id: str) -> List[str]:
    log_file = ACCESS_LOG_DIR / f"{pac_id}.log"
    if not log_file.exists():
        return []
    with open(log_file, "r") as f:
        return f.read().splitlines()

def delete_access_log(pac_id: str) -> bool:
    """
    Delete the access log file for a specific PAC file
    :param pac_id: ID of the PAC file
    :return: True if file was deleted, False if it didn't exist
    """
    log_file = ACCESS_LOG_DIR / f"{pac_id}.log"
    if log_file.exists():
        log_file.unlink()
        return True
    return False