"""Strict schema validation for every tool argument (pydantic v2).

extra="forbid" means the model cannot smuggle extra arguments such as tenant_id, role or
from_addr: identity and tenant always come from the authenticated Principal instead.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

ASSET_ID = r"^[A-Z]{3}-\d{3}$"
SAFE_TEXT = r"^[^<>`{}\\;]*$"  # no markup/SQL-ish metacharacters in short free-text fields

EquipmentStatus = Literal["in_service", "advisory", "out_of_service"]
Category = Literal["ventilator", "infusion_pump", "defibrillator", "generator", "sterilizer", "hvac", "imaging"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ListEquipmentArgs(Strict):
    status: Optional[EquipmentStatus] = None
    category: Optional[Category] = None


class GetEquipmentArgs(Strict):
    asset_id: str = Field(pattern=ASSET_ID)


class ListWorkOrdersArgs(Strict):
    status: Optional[Literal["open", "in_progress", "closed"]] = None


class SearchDocsArgs(Strict):
    query: str = Field(min_length=2, max_length=200)


class CreateWorkOrderArgs(Strict):
    asset_id: str = Field(pattern=ASSET_ID)
    priority: Literal["low", "medium", "high", "critical"]
    summary: str = Field(min_length=5, max_length=200, pattern=SAFE_TEXT)


class SendEmailArgs(Strict):
    to: str = Field(max_length=120, pattern=r"^[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}$")
    subject: str = Field(min_length=1, max_length=120, pattern=r"^[^\r\n<>]*$")
    body: str = Field(min_length=1, max_length=2000)

    @field_validator("to")
    @classmethod
    def single_recipient(cls, v: str) -> str:
        if "," in v or ";" in v:
            raise ValueError("exactly one recipient is allowed")
        return v


class SetPreferenceArgs(Strict):
    key: Literal["language", "response_style"]
    value: str

    @field_validator("value")
    @classmethod
    def allowed_value(cls, v: str, info) -> str:
        allowed = {"language": {"en", "ar"}, "response_style": {"brief", "detailed"}}
        key = info.data.get("key")
        if key and v not in allowed[key]:
            raise ValueError(f"value for {key} must be one of {sorted(allowed[key])}")
        return v


TOOL_ARG_SCHEMAS: dict[str, type[Strict]] = {
    "list_equipment": ListEquipmentArgs,
    "get_equipment": GetEquipmentArgs,
    "list_work_orders": ListWorkOrdersArgs,
    "search_docs": SearchDocsArgs,
    "create_work_order": CreateWorkOrderArgs,
    "send_email": SendEmailArgs,
    "set_preference": SetPreferenceArgs,
}


def validate_args(tool_name: str, args: dict) -> tuple[Optional[Strict], Optional[str]]:
    try:
        return TOOL_ARG_SCHEMAS[tool_name].model_validate(args), None
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'args'}: {e['msg']}" for e in exc.errors())
        return None, f"INVALID: {problems}"
