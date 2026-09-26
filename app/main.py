"""公开档案敏感片段遮盖 API。

启动：``uvicorn app.main:app --host 0.0.0.0 --port 8000``
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

from anyio import to_thread
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import publishing
from .redaction import (
    Edit,
    Fragment,
    apply_edits,
    mask_text,
    migrate_fragment,
    select_fragments,
    select_fragments_with_budget,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 启动时确保凭证表存在（幂等）。
    publishing.init_db()
    yield


app = FastAPI(
    title="敏感片段遮盖 API",
    version="1.3.0",
    lifespan=lifespan,
    description=(
        "提交原文及候选片段（含唯一 ID、正整数权重、左闭右开码点区间），"
        "返回互不重叠的最优入选组合、落选 ID 与等长遮盖文本。"
        "支持按码点区间编辑修订原文：作废旧片段、迁移保留片段后再选择遮盖；"
        "也支持通过 /redact/budget 限定遮盖码点总预算。"
        "POST /redact/publish 可发布脱敏凭证：仅持久化遮盖正文、入选区间与"
        "加盐原文摘要（不保存原文），凭证串成 SHA-256 哈希链，"
        "可经 /redact/publish/{id}/verify 凭客户端留存的链值核验。"
    ),
)


# /docs 中展示的请求体 JSON Schema；实际校验由 validate_payload 严格执行。
REDACT_REQUEST_SCHEMA = {
    "type": "object",
    "required": ["text", "fragments"],
    "properties": {
        "text": {
            "type": "string",
            "description": "待处理的原文，位置按 Unicode 码点计数",
        },
        "fragments": {
            "type": "array",
            "description": "候选片段，允许重叠；所有 ID 必须同为整数或同为字符串",
            "items": {
                "type": "object",
                "required": ["id", "weight", "start", "end"],
                "properties": {
                    "id": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                        "description": "片段唯一 ID，不可重复",
                    },
                    "weight": {
                        "type": "integer",
                        "exclusiveMinimum": 0,
                        "description": "正整数权重",
                    },
                    "start": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "左闭右开起始码点位置（含）",
                    },
                    "end": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "左闭右开结束码点位置（不含）",
                    },
                },
            },
        },
    },
    "example": {
        "text": "你好，世界！",
        "fragments": [
            {"id": 1, "weight": 5, "start": 0, "end": 2},
            {"id": 2, "weight": 3, "start": 3, "end": 5},
        ],
    },
}


# /redact/budget 的请求体 JSON Schema；max_masked_chars 的语义校验由
# validate_budget_payload 执行。
BUDGET_REQUEST_SCHEMA = {
    "type": "object",
    "required": ["text", "fragments", "max_masked_chars"],
    "properties": {
        "text": REDACT_REQUEST_SCHEMA["properties"]["text"],
        "fragments": REDACT_REQUEST_SCHEMA["properties"]["fragments"],
        "max_masked_chars": {
            "type": "integer",
            "minimum": 0,
            "description": "遮盖码点总数预算，非负整数；为 0 时不遮盖任何码点",
        },
    },
    "example": {
        "text": "你好，世界！",
        "fragments": [
            {"id": 1, "weight": 5, "start": 0, "end": 3},
            {"id": 2, "weight": 3, "start": 0, "end": 2},
            {"id": 3, "weight": 1, "start": 2, "end": 5},
        ],
        "max_masked_chars": 3,
    },
}


# /redact/revise 的请求体 JSON Schema；edits 的语义校验由 validate_revise_payload 执行。
REVISE_REQUEST_SCHEMA = {
    "type": "object",
    "required": ["text", "fragments", "edits"],
    "properties": {
        "text": REDACT_REQUEST_SCHEMA["properties"]["text"],
        "fragments": REDACT_REQUEST_SCHEMA["properties"]["fragments"],
        "edits": {
            "type": "array",
            "description": (
                "按原文码点定位的编辑，一次性应用；区间须互不重叠，"
                "同一位置不允许多次插入"
            ),
            "items": {
                "type": "object",
                "required": ["start", "end", "replacement"],
                "properties": {
                    "start": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "编辑起始码点位置（含）",
                    },
                    "end": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "编辑结束码点位置（不含）；等于 start 时为纯插入",
                    },
                    "replacement": {
                        "type": "string",
                        "description": "替换文本；空字符串表示删除该区间",
                    },
                },
            },
        },
    },
    "example": {
        "text": "你好，世界！",
        "fragments": [
            {"id": 1, "weight": 5, "start": 0, "end": 2},
            {"id": 2, "weight": 3, "start": 3, "end": 5},
        ],
        "edits": [
            {"start": 2, "end": 3, "replacement": "！"},
            {"start": 6, "end": 6, "replacement": "再见"},
        ],
    },
}


# /redact/publish 的请求体与 /redact 相同（text + fragments）；
# 复用 REDACT_REQUEST_SCHEMA 在 /docs 展示相同的请求结构。


class RedactOut(BaseModel):
    selected_ids: list[int | str] = Field(..., description="入选片段 ID（升序）")
    rejected_ids: list[int | str] = Field(..., description="落选片段 ID（升序）")
    masked_text: str = Field(..., description="入选片段以等长 █ 遮盖后的正文")


class BudgetOut(BaseModel):
    selected_ids: list[int | str] = Field(..., description="入选片段 ID（升序）")
    rejected_ids: list[int | str] = Field(..., description="落选片段 ID（升序）")
    masked_text: str = Field(..., description="入选片段以等长 █ 遮盖后的正文")
    used_chars: int = Field(
        ..., description="入选片段实际遮盖的码点总数（不超过 max_masked_chars）"
    )


class ReviseOut(BaseModel):
    revised_text: str = Field(..., description="应用全部编辑后的原文")
    invalidated_ids: list[int | str] = Field(
        ..., description="被编辑波及而作废的片段 ID（升序）"
    )
    selected_ids: list[int | str] = Field(
        ..., description="保留片段中入选的 ID（升序）"
    )
    rejected_ids: list[int | str] = Field(
        ..., description="保留片段中落选的 ID（升序，不含作废）"
    )
    masked_text: str = Field(..., description="修订后正文中入选片段以等长 █ 遮盖的结果")


class PublishOut(BaseModel):
    credential_id: int = Field(..., description="凭证编号，从 1 开始连续递增")
    selected_ids: list[int | str] = Field(..., description="入选片段 ID（升序）")
    masked_text: str = Field(..., description="入选片段以等长 █ 遮盖后的正文（已持久化）")
    chain_value: str = Field(
        ..., description="本凭证链值（64 位十六进制 SHA-256），由客户端留存用于核验"
    )


class VerifyOut(BaseModel):
    credential_id: int = Field(..., description="被核验的凭证编号")
    valid: bool = Field(..., description="链完整且与客户端留存链值一致时为 true")
    first_broken_id: int | None = Field(
        ..., description="首个断裂编号；无断裂时为 null"
    )
    chain_value_matches: bool = Field(
        ..., description="重算所得链值（断裂时为库存链值）是否等于客户端留存链值"
    )
    server_chain_value: str = Field(
        ..., description="服务端截至该凭证的链值（重算结果或当前库存值）"
    )


def _bad(message: str) -> ValueError:
    """构造带统一中文消息的校验错误。"""
    return ValueError(message)


def validate_payload(payload: Any) -> tuple[str, list[Fragment]]:
    """严格校验 /redact 请求体，返回 ``(原文, Fragment 列表)``。

    任何不合法输入（类型错误、越界、空片段、重复 ID 等）均抛出
    ``ValueError``，由上层转为 HTTP 400。
    """
    if not isinstance(payload, dict):
        raise _bad("请求体必须是 JSON 对象，包含 text 与 fragments 字段")
    return _validate_text_and_fragments(payload)


def validate_budget_payload(payload: Any) -> tuple[str, list[Fragment], int]:
    """严格校验 /redact/budget 请求体。

    返回 ``(原文, Fragment 列表, 预算)``；``text`` 与 ``fragments`` 的
    校验规则与 :func:`validate_payload` 完全一致，``max_masked_chars``
    必须是非负整数（不接受 bool、float 或字符串）。
    """
    if not isinstance(payload, dict):
        raise _bad(
            "请求体必须是 JSON 对象，包含 text、fragments 与 max_masked_chars 字段"
        )
    text, fragments = _validate_text_and_fragments(payload)

    if "max_masked_chars" not in payload:
        raise _bad("缺少字段：max_masked_chars")
    budget = payload["max_masked_chars"]
    if isinstance(budget, bool) or not isinstance(budget, int):
        raise _bad("max_masked_chars 必须是非负整数")
    if budget < 0:
        raise _bad("max_masked_chars 必须是非负整数")
    return text, fragments, budget


def validate_revise_payload(payload: Any) -> tuple[str, list[Fragment], list[Edit]]:
    """严格校验 /redact/revise 请求体，返回 ``(原文, Fragment 列表, Edit 列表)``。

    片段与编辑区间均按原文码点定位；编辑越界、逆序、彼此重叠或同一位置
    多次插入均抛出 ``ValueError``，由上层转为 HTTP 400。
    """
    if not isinstance(payload, dict):
        raise _bad("请求体必须是 JSON 对象，包含 text、fragments 与 edits 字段")
    text, fragments = _validate_text_and_fragments(payload)

    if "edits" not in payload:
        raise _bad("缺少字段：edits")
    edits = _validate_edits(text, payload["edits"])
    return text, fragments, edits


def _validate_text_and_fragments(payload: dict) -> tuple[str, list[Fragment]]:
    """校验 ``text`` 与 ``fragments`` 字段（``payload`` 已确认是对象）。"""
    if "text" not in payload:
        raise _bad("缺少字段：text")
    text = payload["text"]
    if not isinstance(text, str):
        raise _bad("text 必须是字符串")

    if "fragments" not in payload:
        raise _bad("缺少字段：fragments")
    raw_fragments = payload["fragments"]
    if not isinstance(raw_fragments, list):
        raise _bad("fragments 必须是数组")

    fragments: list[Fragment] = []
    id_type: type | None = None
    seen_ids: set[Any] = set()

    for index, item in enumerate(raw_fragments):
        where = f"fragments[{index}]"
        if not isinstance(item, dict):
            raise _bad(f"{where} 必须是对象")

        for field in ("id", "weight", "start", "end"):
            if field not in item:
                raise _bad(f"{where} 缺少字段：{field}")

        raw_id = item["id"]
        # bool 是 int 的子类，必须显式排除；不接受 float（包括 1.0）。
        if isinstance(raw_id, bool) or not isinstance(raw_id, (int, str)):
            raise _bad(f"{where}.id 必须是整数或字符串")
        if isinstance(raw_id, str) and raw_id == "":
            raise _bad(f"{where}.id 不能为空字符串")
        if id_type is None:
            id_type = type(raw_id)
        elif not isinstance(raw_id, id_type):
            raise _bad(
                f"{where}.id 类型 {type(raw_id).__name__} 与既有 ID 类型 "
                f"{id_type.__name__} 不一致；一次请求内所有 ID 必须同为整数或同为字符串"
            )
        if raw_id in seen_ids:
            raise _bad(f"重复的片段 ID：{raw_id!r}")
        seen_ids.add(raw_id)

        weight = item["weight"]
        if isinstance(weight, bool) or not isinstance(weight, int):
            raise _bad(f"{where}.weight 必须是整数")
        if weight <= 0:
            raise _bad(f"{where}.weight 必须是正整数")

        start = item["start"]
        end = item["end"]
        if isinstance(start, bool) or not isinstance(start, int):
            raise _bad(f"{where}.start 必须是整数")
        if isinstance(end, bool) or not isinstance(end, int):
            raise _bad(f"{where}.end 必须是整数")
        if start < 0:
            raise _bad(f"{where}.start 不能为负数")
        if end > len(text):
            raise _bad(
                f"{where} 越界：end={end} 超出原文码点长度 {len(text)}"
            )
        if start >= end:
            raise _bad(
                f"{where} 是空片段或区间非法：要求 0 <= start < end，"
                f"实际 start={start}, end={end}"
            )

        fragments.append(Fragment(id=raw_id, weight=weight, start=start, end=end))

    return text, fragments


def _validate_edits(text: str, raw_edits: Any) -> list[Edit]:
    """校验编辑列表，返回按原文定位、互不重叠的 ``Edit`` 列表。"""
    if not isinstance(raw_edits, list):
        raise _bad("edits 必须是数组")

    edits: list[Edit] = []
    for index, item in enumerate(raw_edits):
        where = f"edits[{index}]"
        if not isinstance(item, dict):
            raise _bad(f"{where} 必须是对象")

        for field in ("start", "end", "replacement"):
            if field not in item:
                raise _bad(f"{where} 缺少字段：{field}")

        start = item["start"]
        end = item["end"]
        replacement = item["replacement"]
        if isinstance(start, bool) or not isinstance(start, int):
            raise _bad(f"{where}.start 必须是整数")
        if isinstance(end, bool) or not isinstance(end, int):
            raise _bad(f"{where}.end 必须是整数")
        if not isinstance(replacement, str):
            raise _bad(f"{where}.replacement 必须是字符串")
        if start < 0:
            raise _bad(f"{where}.start 不能为负数")
        if end > len(text):
            raise _bad(f"{where} 越界：end={end} 超出原文码点长度 {len(text)}")
        if start > end:
            raise _bad(
                f"{where} 区间逆序：要求 start <= end，实际 start={start}, end={end}"
            )

        edits.append(Edit(start=start, end=end, replacement=replacement))

    # 重叠检测：按 (start, end) 排序后只需检查相邻两项。
    # 相邻（prev.end == curr.start）不算重叠，但同一位置的两次插入必须拒绝。
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    for prev, curr in zip(ordered, ordered[1:]):
        if curr.start < prev.end:
            raise _bad(
                f"编辑区间彼此重叠：[{prev.start}, {prev.end}) 与 "
                f"[{curr.start}, {curr.end})"
            )
        if prev.is_insertion and curr.is_insertion and prev.start == curr.start:
            raise _bad(f"同一位置 {curr.start} 的多次插入不被允许")

    return edits


@app.exception_handler(ValueError)
async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"service": "sensitive-fragment-redaction", "docs": "/docs"}


@app.get("/health", tags=["其他"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/redact",
    response_model=RedactOut,
    tags=["遮盖"],
    summary="选择互不重叠片段并遮盖原文",
    openapi_extra={"requestBody": {"content": {"application/json": {"schema": REDACT_REQUEST_SCHEMA}}}},
)
async def redact(request: Request) -> RedactOut:
    # 自行解析 JSON：语法错误（空请求体、非法 JSON）统一转为 400；
    # 字段语义全部由 validate_payload 统一校验。
    try:
        payload = await request.json()
    except ValueError:
        raise _bad("请求体不是合法的 JSON")
    text, fragments = validate_payload(payload)

    selected = select_fragments(fragments)

    by_id = {f.id: f for f in fragments}
    chosen = [by_id[fragment_id] for fragment_id in selected]
    all_ids = sorted(f.id for f in fragments)

    masked = mask_text(text, chosen)
    return RedactOut(
        selected_ids=list(selected),
        rejected_ids=[i for i in all_ids if i not in set(selected)],
        masked_text=masked,
    )


@app.post(
    "/redact/budget",
    response_model=BudgetOut,
    tags=["遮盖"],
    summary="在遮盖码点预算内选择互不重叠片段并遮盖原文",
    openapi_extra={"requestBody": {"content": {"application/json": {"schema": BUDGET_REQUEST_SCHEMA}}}},
)
async def redact_budget(request: Request) -> BudgetOut:
    try:
        payload = await request.json()
    except ValueError:
        raise _bad("请求体不是合法的 JSON")
    text, fragments, budget = validate_budget_payload(payload)

    selected = select_fragments_with_budget(fragments, budget)

    by_id = {f.id: f for f in fragments}
    chosen = [by_id[fragment_id] for fragment_id in selected]
    all_ids = sorted(f.id for f in fragments)

    masked = mask_text(text, chosen)
    used_chars = sum(frag.length for frag in chosen)
    return BudgetOut(
        selected_ids=list(selected),
        rejected_ids=[i for i in all_ids if i not in set(selected)],
        masked_text=masked,
        used_chars=used_chars,
    )


@app.post(
    "/redact/revise",
    response_model=ReviseOut,
    tags=["遮盖"],
    summary="应用编辑修订原文，迁移片段后再选择遮盖",
    openapi_extra={"requestBody": {"content": {"application/json": {"schema": REVISE_REQUEST_SCHEMA}}}},
)
async def revise(request: Request) -> ReviseOut:
    try:
        payload = await request.json()
    except ValueError:
        raise _bad("请求体不是合法的 JSON")
    text, fragments, edits = validate_revise_payload(payload)

    revised = apply_edits(text, edits)

    kept: list[Fragment] = []
    invalidated: list[int | str] = []
    for frag in fragments:
        migrated = migrate_fragment(frag, edits)
        if migrated is None:
            invalidated.append(frag.id)
        else:
            kept.append(migrated)

    selected = select_fragments(kept)
    selected_set = set(selected)
    by_id = {f.id: f for f in kept}
    chosen = [by_id[fragment_id] for fragment_id in selected]

    masked = mask_text(revised, chosen)
    return ReviseOut(
        revised_text=revised,
        invalidated_ids=sorted(invalidated),
        selected_ids=list(selected),
        rejected_ids=sorted(f.id for f in kept if f.id not in selected_set),
        masked_text=masked,
    )


@app.post(
    "/redact/publish",
    response_model=PublishOut,
    tags=["脱敏发布凭证"],
    summary="按 /redact 规则遮盖并发布脱敏凭证（哈希链）",
    openapi_extra={"requestBody": {"content": {"application/json": {"schema": REDACT_REQUEST_SCHEMA}}}},
)
async def publish(request: Request) -> PublishOut:
    # text / fragments 的校验与选段规则与 POST /redact 完全一致。
    try:
        payload = await request.json()
    except ValueError:
        raise _bad("请求体不是合法的 JSON")
    text, fragments = validate_payload(payload)

    selected = select_fragments(fragments)
    by_id = {f.id: f for f in fragments}
    chosen = [by_id[fragment_id] for fragment_id in selected]
    masked = mask_text(text, chosen)

    # 仅持久化：遮盖正文、入选码点区间、带随机盐的原文摘要；原文不入库。
    # SQLite 事务（BEGIN IMMEDIATE）在工作线程中同步执行，
    # 保证并发请求的编号与链顺序一致。
    ranges = [(frag.start, frag.end) for frag in chosen]
    text_digest = publishing.salted_text_digest(text)
    credential = await to_thread.run_sync(
        publishing.publish_credential, masked, ranges, text_digest
    )
    return PublishOut(
        credential_id=credential.seq,
        selected_ids=list(selected),
        masked_text=credential.masked_text,
        chain_value=credential.chain_value,
    )


@app.get(
    "/redact/publish/{credential_id}/verify",
    response_model=VerifyOut,
    tags=["脱敏发布凭证"],
    summary="凭客户端留存的链值核验截至指定凭证的哈希链",
)
async def verify_published(
    credential_id: int,
    chain_value: str | None = Query(
        default=None,
        description="发布时客户端留存的该凭证链值（64 位十六进制 SHA-256）",
    ),
) -> VerifyOut:
    if chain_value is None:
        raise _bad("缺少查询参数：chain_value")
    if not _is_hex64(chain_value):
        raise _bad("chain_value 必须是 64 位小写十六进制 SHA-256 摘要")

    credential = await to_thread.run_sync(publishing.get_credential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="凭证不存在")

    records = await to_thread.run_sync(
        publishing.list_credentials_through, credential_id
    )
    broken = publishing.first_chain_break(records, credential_id)
    # 链断裂时无法按链重算出有意义的尾链值，直接返回库存尾链值供排查。
    server_chain_value = (
        credential.chain_value if broken is not None else records[-1].chain_value
    )
    chain_value_matches = (
        broken is None
        and _equal_hex_digest(server_chain_value, chain_value)
    )
    return VerifyOut(
        credential_id=credential_id,
        valid=chain_value_matches,
        first_broken_id=broken,
        chain_value_matches=chain_value_matches,
        server_chain_value=server_chain_value,
    )


def _is_hex64(value: str) -> bool:
    """``value`` 是否为 64 位小写十六进制字符串（与 sha256().hexdigest() 同形）。"""
    return (
        len(value) == 64
        and all(
            ("0" <= char <= "9") or ("a" <= char <= "f") for char in value
        )
    )


def _equal_hex_digest(left: str, right: str) -> bool:
    """恒定时间比较两个十六进制摘要，避免核验接口的计时侧信道。"""
    return secrets.compare_digest(left, right)
