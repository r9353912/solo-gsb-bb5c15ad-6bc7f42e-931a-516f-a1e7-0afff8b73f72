"""脱敏发布凭证：持久化、哈希链与并发的单元测试。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app import publishing


@pytest.fixture
def db(tmp_path: str) -> str:
    path = str(tmp_path / "publish.db")
    publishing.init_db(path)
    return path


def _stored_raw_text_is_not_persisted(db: str, text: str) -> None:
    """直接扫描数据库文件，确认原文未以任何编码落盘。"""
    for needle in (text.encode("utf-8"), text.encode("utf-16-le"), text.encode("utf-32-le")):
        assert needle not in open(db, "rb").read()


def test_salted_digest_is_sha256_of_salt_and_text() -> None:
    digest = publishing.salted_text_digest("机密")
    salt_hex, hash_hex = digest.split("$")
    assert len(salt_hex) == 64  # 32 字节盐
    assert len(hash_hex) == 64
    expected = hashlib.sha256(bytes.fromhex(salt_hex) + "机密".encode("utf-8")).hexdigest()
    assert hash_hex == expected


def test_salted_digest_uses_random_salt() -> None:
    assert publishing.salted_text_digest("机密") != publishing.salted_text_digest("机密")


def test_first_credential_uses_genesis_chain_value(db: str) -> None:
    digest = publishing.salted_text_digest("abc")
    cred = publishing.publish_credential("██c", [(0, 2)], digest, path=db)
    assert cred.seq == 1
    canonical = publishing.canonical_credential(
        1, "██c", ((0, 2),), digest, publishing.GENESIS_CHAIN_VALUE
    )
    assert cred.chain_value == hashlib.sha256(canonical).hexdigest()


def test_publish_returns_only_persisted_fields_and_no_plaintext(db: str) -> None:
    text = "机密原文不可落盘"
    digest = publishing.salted_text_digest(text)
    cred = publishing.publish_credential("████不可落盘", [(0, 4)], digest, path=db)
    assert cred.masked_text == "████不可落盘"
    assert cred.ranges == ((0, 4),)
    assert cred.text_digest == digest
    _stored_raw_text_is_not_persisted(db, text)


def test_ranges_sorted_and_serialized_compactly(db: str) -> None:
    digest = publishing.salted_text_digest("abcdef")
    cred = publishing.publish_credential(
        "██████", [(3, 6), (0, 3)], digest, path=db
    )
    assert cred.ranges == ((0, 3), (3, 6))
    loaded = publishing.get_credential(1, path=db)
    assert loaded is not None
    assert loaded.ranges == ((0, 3), (3, 6))


def test_chain_links_to_previous_stored_value(db: str) -> None:
    first = publishing.publish_credential(
        "█bc", [(0, 1)], publishing.salted_text_digest("abc"), path=db
    )
    second = publishing.publish_credential(
        "██c", [(0, 2)], publishing.salted_text_digest("abc"), path=db
    )
    assert first.seq == 1 and second.seq == 2
    canonical = publishing.canonical_credential(
        2, "██c", ((0, 2),), second.text_digest, first.chain_value
    )
    assert second.chain_value == hashlib.sha256(canonical).hexdigest()


def test_canonical_content_is_deterministic() -> None:
    kwargs = dict(
        seq=1,
        masked_text="你█",
        ranges=((1, 2),),
        text_digest="abcd$1234",
        prev_chain_value=publishing.GENESIS_CHAIN_VALUE,
    )
    a = publishing.canonical_credential(**kwargs)
    b = publishing.canonical_credential(**kwargs)
    assert a == b
    # 非 ASCII 直出、无空白、键序固定
    decoded = json.loads(a.decode("utf-8"))
    assert decoded["masked_text"] == "你█"
    assert b", " not in a and b": " not in a.replace(b":", b"")


def test_first_chain_break_none_on_intact_chain(db: str) -> None:
    publishing.publish_credential(
        "█bc", [(0, 1)], publishing.salted_text_digest("abc"), path=db
    )
    publishing.publish_credential(
        "██c", [(0, 2)], publishing.salted_text_digest("abc"), path=db
    )
    records = publishing.list_credentials_through(2, path=db)
    assert publishing.first_chain_break(records, 2) is None


@pytest.mark.parametrize("tamper_seq", [1, 2, 3])
def test_tampered_masked_text_detected(db: str, tamper_seq: int) -> None:
    for length in (1, 2, 3):
        publishing.publish_credential(
            "█" * length + "abc"[length:],
            [(0, length)],
            publishing.salted_text_digest("abc"),
            path=db,
        )
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE redaction_publish SET masked_text = ? WHERE seq = ?",
        ("被篡改", tamper_seq),
    )
    conn.commit()
    conn.close()

    records = publishing.list_credentials_through(3, path=db)
    # 被篡改条目即首个断裂点（其后记录引用的链值也会失配，
    # 但首个断裂点必须是被改的那条）。
    assert publishing.first_chain_break(records, 3) == tamper_seq


def test_tampered_chain_value_detected(db: str) -> None:
    publishing.publish_credential(
        "█bc", [(0, 1)], publishing.salted_text_digest("abc"), path=db
    )
    second = publishing.publish_credential(
        "██c", [(0, 2)], publishing.salted_text_digest("abc"), path=db
    )
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE redaction_publish SET chain_value = ? WHERE seq = ?",
        ("f" * 64, second.seq),
    )
    conn.commit()
    conn.close()

    records = publishing.list_credentials_through(2, path=db)
    assert publishing.first_chain_break(records, 2) == 2


def test_missing_record_reported_as_first_gap(db: str) -> None:
    publishing.publish_credential(
        "█bc", [(0, 1)], publishing.salted_text_digest("abc"), path=db
    )
    publishing.publish_credential(
        "██c", [(0, 2)], publishing.salted_text_digest("abc"), path=db
    )
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM redaction_publish WHERE seq = 1")
    conn.commit()
    conn.close()

    records = publishing.list_credentials_through(2, path=db)
    assert publishing.first_chain_break(records, 2) == 1


def test_concurrent_publish_gets_distinct_sequential_ids_and_chain(db: str) -> None:
    count = 40

    def publish_one(i: int) -> publishing.StoredCredential:
        text = f"原文{i}号"
        masked = "█" + text[1:]
        return publishing.publish_credential(
            masked, [(0, 1)], publishing.salted_text_digest(text), path=db
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        credentials = list(pool.map(publish_one, range(count)))

    assert sorted(c.seq for c in credentials) == list(range(1, count + 1))

    records = publishing.list_credentials_through(count, path=db)
    assert [r.seq for r in records] == list(range(1, count + 1))
    assert publishing.first_chain_break(records, count) is None

    # 链值全部互不相同且均为 64 位十六进制
    values = {r.chain_value for r in records}
    assert len(values) == count
    assert all(len(v) == 64 for v in values)


def test_get_credential_missing_returns_none(db: str) -> None:
    assert publishing.get_credential(1, path=db) is None


def _publish_three(db: str) -> None:
    for length in (1, 2, 3):
        publishing.publish_credential(
            "█" * length + "abc"[length:],
            [(0, length)],
            publishing.salted_text_digest("abc"),
            path=db,
        )


def test_export_returns_ordered_records_through_tail(db: str) -> None:
    _publish_three(db)
    records = publishing.export_credentials_through(2, path=db)
    assert records is not None
    assert [r.seq for r in records] == [1, 2]
    # 与逐条读取的内容一致
    assert records[1] == publishing.get_credential(2, path=db)


def test_export_missing_tail_returns_none(db: str) -> None:
    assert publishing.export_credentials_through(1, path=db) is None
    _publish_three(db)
    assert publishing.export_credentials_through(4, path=db) is None


def test_export_with_gap_still_returns_existing_records(db: str) -> None:
    _publish_three(db)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM redaction_publish WHERE seq = 2")
    conn.commit()
    conn.close()

    records = publishing.export_credentials_through(3, path=db)
    assert records is not None
    assert [r.seq for r in records] == [1, 3]
    # 缺口由核验方检出：首个断裂编号为 2
    assert publishing.first_chain_break(records, 3) == 2


def test_init_db_is_idempotent(db: str) -> None:
    publishing.init_db(db)
    publishing.init_db(db)
    # 表存在且可写
    cred = publishing.publish_credential(
        "█", [(0, 1)], publishing.salted_text_digest("a"), path=db
    )
    assert cred.seq == 1
