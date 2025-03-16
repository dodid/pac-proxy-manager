from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel


class PACFileBase(BaseModel):
    name: str
    content: str
    proxy_url: str
    editor_content: Dict[str, str]

class PACFileCreate(PACFileBase):
    pass

class PACFileUpdate(PACFileBase):
    pass

class PACFile(PACFileBase):
    id: str
    created_at: str
    updated_at: Optional[str]
    is_active: bool

    def created_at_datetime(self) -> datetime:
        return datetime.fromisoformat(self.created_at)

    def updated_at_datetime(self) -> Optional[datetime]:
        return datetime.fromisoformat(self.updated_at) if self.updated_at else None