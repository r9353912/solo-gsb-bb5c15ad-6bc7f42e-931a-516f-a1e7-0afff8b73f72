"""脱敏发布凭证的持久化与哈希链。

本模块与 HTTP 框架解耦，便于单元测试。凭证只持久化：

- 遮盖正文 ``masked_text``；
- 入选码点区间 ``ranges``（左闭右开，按起点升序）；
- 带随机盐的原文 SHA-256 摘要 ``text_digest``（**不保存原文**，格式
  为 ``"<盐 hex>$<sha256(盐 || 原文 UTF-8) hex>"``）；
- 凭证编号 ``seq`` 与链值 ``chain_value``。

每条新凭证的链值为对“规范化凭证内容 + 前一链值”取 SHA-256：

    chain[0]  = 64 个 0（创世链值，不入库）
    chain[i]  = sha256(canonical(seq, masked_text, ranges,
                                 text_digest, chain[i-1]))

规范化内容为 ``json.dumps(..., ensure_ascii=False,
sort_keys=True, separators=(",", ":"))`` 的 UTF-8 字节，字段集合固定，
保证任何实现重算结果一致。

发布在单条 SQLite 事务中以 ``BEGIN IMMEDIATE`` 立即获取写锁，
配合 ``busy_timeout``，使并发请求的编号与链顺序严格串行一致。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass

# 创世链值：第一条凭证的“前一链值”，不写入数据库。
GENESIS_CHAIN_VALUE = "0" * 64

# 数据库默认路径；可用环境变量 REDACTION_DB_PATH 覆盖（容器内为 /data/redaction.db）。
DEFAULT_DB_PATH = os.path.join("data", "redaction.db")

# 与 sqlite3.connect(timeout=...) 配套：锁竞争时最多等待 30 秒而非立即报错。
BUSY_TIMEOUT_MS = 30_000

_SALT_BYTES = 32


@dataclass(frozen=True)
class StoredCredential:
    """一条已持久化的脱敏发布凭证（不含原文）。"""

    seq: int
    masked_text: str
    ranges: tuple[tuple[int, int], ...]
    text_digest: str
    chain_value: str


def db_path() -> str:
    """当前生效的 SQLite 路径（每次调用读取环境变量，便于测试覆盖）。"""
    return os.environ.get("REDACTION_DB_PATH", DEFAULT_DB_PATH)


def salted_text_digest(text: str) -> str:
    """计算带随机盐的原文 SHA-256 摘要。

    返回持久化字符串 ``"<盐 hex>$<摘要 hex>"``，其中
    ``摘要 = sha256(盐字节 || 原文 UTF-8 字节)``。随机盐使相同原文的
    摘要也互不相同，避免按摘要反查常见原文。原文本身不入库。
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.sha256(salt + text.encode("utf-8")).hexdigest()
    return f"{salt.hex()}${digest}"


def canonical_credential(
    seq: int,
    masked_text: str,
    ranges: tuple[tuple[int, int], ...] | list[list[int]],
    text_digest: str,
    prev_chain_value: str,
) -> bytes:
    """构造参与链值计算的规范化凭证内容（UTF-8 字节）。"""
    payload = {
        "seq": seq,
        "masked_text": masked_text,
        "ranges": [[start, end] for start, end in ranges],
        "text_digest": text_digest,
        "prev_chain_value": prev_chain_value,
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def compute_chain_value(
    seq: int,
    masked_text: str,
    ranges: tuple[tuple[int, int], ...] | list[list[int]],
    text_digest: str,
    prev_chain_value: str,
) -> str:
    """对规范化凭证内容与前一链值取 SHA-256，返回 64 位小写十六进制链值。"""
    return hashlib.sha256(
        canonical_credential(seq, masked_text, ranges, text_digest, prev_chain_value)
    ).hexdigest()


def _connect(path: str) -> sqlite3.Connection:
    """打开到 ``path`` 的短连接：自动建目录、启用 WAL 与忙等待。"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    # isolation_level=None：显式管理事务（BEGIN IMMEDIATE / COMMIT）。
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    # WAL 允许读写并发；写之间仍由库级写锁串行化。
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(path: str | None = None) -> None:
    """创建凭证表（幂等）。"""
    path = path or db_path()
    conn = _connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS redaction_publish (
                seq         INTEGER PRIMARY KEY,
                masked_text TEXT NOT NULL,
                ranges_json TEXT NOT NULL,
                text_digest TEXT NOT NULL,
                chain_value TEXT NOT NULL
            )
            """
        )
    finally:
        conn.close()


def _row_to_credential(row: sqlite3.Row | tuple) -> StoredCredential:
    seq, masked_text, ranges_json, text_digest, chain_value = row
    ranges = tuple((int(start), int(end)) for start, end in json.loads(ranges_json))
    return StoredCredential(
        seq=seq,
        masked_text=masked_text,
        ranges=ranges,
        text_digest=text_digest,
        chain_value=chain_value,
    )


def publish_credential(
    masked_text: str,
    ranges: list[tuple[int, int]] | tuple[tuple[int, int], ...],
    text_digest: str,
    path: str | None = None,
) -> StoredCredential:
    """在单个 SQLite 事务内追加一条凭证并计算链值。

    ``BEGIN IMMEDIATE`` 在事务开始时即获取写锁：并发发布只会串行排队，
    “读取最大编号 → 分配新编号 → 写入”不会交错，从而保证编号连续、
    每条链值都引用提交时的前一链值。
    """
    path = path or db_path()
    ordered = tuple(sorted(ranges, key=lambda r: (r[0], r[1])))
    ranges_json = json.dumps(
        [[start, end] for start, end in ordered], separators=(",", ":")
    )
    conn = _connect(path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT seq, chain_value FROM redaction_publish "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row is None:
                seq = 1
                prev_chain_value = GENESIS_CHAIN_VALUE
            else:
                seq = int(row[0]) + 1
                prev_chain_value = row[1]

            chain_value = compute_chain_value(
                seq, masked_text, ordered, text_digest, prev_chain_value
            )
            conn.execute(
                "INSERT INTO redaction_publish "
                "(seq, masked_text, ranges_json, text_digest, chain_value) "
                "VALUES (?, ?, ?, ?, ?)",
                (seq, masked_text, ranges_json, text_digest, chain_value),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()

    return StoredCredential(
        seq=seq,
        masked_text=masked_text,
        ranges=ordered,
        text_digest=text_digest,
        chain_value=chain_value,
    )


def get_credential(seq: int, path: str | None = None) -> StoredCredential | None:
    """按编号读取凭证；不存在返回 ``None``。"""
    path = path or db_path()
    conn = _connect(path)
    try:
        row = conn.execute(
            "SELECT seq, masked_text, ranges_json, text_digest, chain_value "
            "FROM redaction_publish WHERE seq = ?",
            (seq,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_credential(row) if row is not None else None


def list_credentials_through(
    tail_seq: int, path: str | None = None
) -> list[StoredCredential]:
    """按编号升序返回 ``1..tail_seq`` 范围内已持久化的凭证。"""
    path = path or db_path()
    conn = _connect(path)
    try:
        rows = conn.execute(
            "SELECT seq, masked_text, ranges_json, text_digest, chain_value "
            "FROM redaction_publish WHERE seq <= ? ORDER BY seq ASC",
            (tail_seq,),
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_credential(row) for row in rows]


def first_chain_break(
    records: list[StoredCredential], tail_seq: int
) -> int | None:
    """从创世链值起重算 ``1..tail_seq`` 的链，返回首个断裂编号。

    对每条记录用其规范化内容与前一条（已持久化的）链值重算并比对：

    - 记录缺失或编号不连续时，断裂编号为第一个缺失的编号；
    - 重算链值与库存链值不一致时，断裂编号为该条记录；
    - 全部一致返回 ``None``。
    """
    prev_chain_value = GENESIS_CHAIN_VALUE
    expected = 1
    for record in records:
        if record.seq != expected:
            return expected
        recomputed = compute_chain_value(
            record.seq,
            record.masked_text,
            record.ranges,
            record.text_digest,
            prev_chain_value,
        )
        if not secrets.compare_digest(recomputed, record.chain_value):
            return record.seq
        prev_chain_value = record.chain_value
        expected += 1
    if expected <= tail_seq:
        return expected
    return None
