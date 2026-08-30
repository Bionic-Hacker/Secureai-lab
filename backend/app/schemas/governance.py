from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, field_validator


class AuditLogEntryOut(BaseModel):
    id: int
    occurred_at: datetime
    actor_user_id: Optional[UUID]
    actor_email: Optional[str]
    event_type: str
    event_category: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    outcome: str
    # Matches the ORM attribute name exactly (the model uses a trailing
    # underscore for this field specifically because "metadata" collides
    # with SQLAlchemy's own Declarative Base attribute) - kept as-is here
    # rather than aliased, to avoid a subtle mismatch between what
    # from_attributes reads and what gets serialized.
    metadata_: dict

    class Config:
        from_attributes = True

    @field_validator("ip_address", mode="before")
    @classmethod
    def _coerce_ip(cls, v):
        # Postgres INET columns are often returned by the driver as
        # ipaddress.IPv4Address/IPv6Address objects, not plain strings.
        # str() handles both that case and an already-string value
        # identically, so this is safe either way rather than assuming
        # one specific driver behavior.
        return str(v) if v is not None else v
