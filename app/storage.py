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
    if not STORAGE_FILE.exists():
        STORAGE_FILE.write_text("{}")

def load_pac_files() -> Dict[str, Any]:
    ensure_storage()
    return json.loads(STORAGE_FILE.read_text())

def save_pac_files(data: Dict[str, Any]):
    ensure_storage()
    STORAGE_FILE.write_text(json.dumps(data, indent=2))

def get_pac_file(file_id: str) -> Dict[str, Any]:
    pac_files = load_pac_files()
    return pac_files.get(file_id)

def save_pac_file(file_id: str, pac_data: Dict[str, Any]):
    pac_files = load_pac_files()
    pac_files[file_id] = pac_data
    save_pac_files(pac_files)

def delete_pac_file(file_id: str):
    pac_files = load_pac_files()
    if file_id in pac_files:
        del pac_files[file_id]
        save_pac_files(pac_files)

def log_access(file_id: str, client_ip: str):
    log_file = ACCESS_LOG_DIR / f"{file_id}.log"
    timestamp = datetime.now().isoformat()
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {client_ip}\n")

def get_access_log(file_id: str) -> List[str]:
    log_file = ACCESS_LOG_DIR / f"{file_id}.log"
    if not log_file.exists():
        return []
    with open(log_file, "r") as f:
        return f.read().splitlines()