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


# ---------------------------------------------------------------------------
# 便携核验包：导出与离线核验
# ---------------------------------------------------------------------------


def _publish_n(db: str, count: int) -> list[publishing.StoredCredential]:
    credentials: list[publishing.StoredCredential] = []
    for i in range(count):
        text = f"原文编号{i}!"
        masked = "█" + text[1:]
        credentials.append(
            publishing.publish_credential(
                masked,
                [(0, 1)],
                publishing.salted_text_digest(text),
                path=db,
            )
        )
    return credentials


def test_export_returns_ordered_records_through_tail(db: str) -> None:
    credentials = _publish_n(db, 3)
    package = publishing.export_package_through(3, path=db)
    assert package is not None
    assert package.tail_seq == 3
    assert [r.seq for r in package.records] == [1, 2, 3]
    for record, credential in zip(package.records, credentials):
        assert isinstance(record, publishing.PackageRecord)
        assert record.seq == credential.seq
        assert record.masked_text == credential.masked_text
        assert record.ranges == credential.ranges
        assert record.text_digest == credential.text_digest
        assert record.chain_value == credential.chain_value

    # 可导出前缀：1..2
    prefix = publishing.export_package_through(2, path=db)
    assert prefix is not None
    assert [r.seq for r in prefix.records] == [1, 2]


def test_export_missing_tail_returns_none(db: str) -> None:
    _publish_n(db, 2)
    assert publishing.export_package_through(3, path=db) is None
    assert publishing.export_package_through(999, path=db) is None
    # 编号从 1 开始：0 与负数也视为不存在
    assert publishing.export_package_through(0, path=db) is None
    assert publishing.export_package_through(-1, path=db) is None


def test_export_package_contains_no_plaintext(db: str) -> None:
    text = "机密原文绝不导出"
    publishing.publish_credential(
        "██" + text[2:],
        [(0, 2)],
        publishing.salted_text_digest(text),
        path=db,
    )
    package = publishing.export_package_through(1, path=db)
    assert package is not None
    serialized = json.dumps(
        {
            "tail_seq": package.tail_seq,
            "records": [
                {
                    "seq": r.seq,
                    "masked_text": r.masked_text,
                    "ranges": [list(x) for x in r.ranges],
                    "text_digest": r.text_digest,
                    "chain_value": r.chain_value,
                }
                for r in package.records
            ],
        },
        ensure_ascii=False,
    )
    assert "机密" not in serialized
    _stored_raw_text_is_not_persisted(db, text)


def test_verify_package_valid_with_client_tail_chain_value(db: str) -> None:
    credentials = _publish_n(db, 3)
    package = publishing.export_package_through(3, path=db)
    assert package is not None
    result = publishing.verify_package(package, credentials[-1].chain_value)
    assert result.valid is True
    assert result.first_broken_id is None
    assert result.chain_value_matches is True
    assert result.server_chain_value == credentials[-1].chain_value
    assert result.tail_seq == 3

    # 前缀包凭当时留存的末端链值同样通过
    prefix = publishing.export_package_through(2, path=db)
    assert prefix is not None
    assert publishing.verify_package(prefix, credentials[1].chain_value).valid is True


def test_verify_package_wrong_saved_value_but_intact(db: str) -> None:
    _publish_n(db, 2)
    package = publishing.export_package_through(2, path=db)
    assert package is not None
    result = publishing.verify_package(package, "f" * 64)
    assert result.valid is False
    assert result.first_broken_id is None
    assert result.chain_value_matches is False
    assert result.server_chain_value == package.records[-1].chain_value


def test_verify_package_detects_gap(db: str) -> None:
    credentials = _publish_n(db, 3)
    package = publishing.export_package_through(3, path=db)
    assert package is not None
    # 删除第 2 条（缺号）
    missing = tuple(r for r in package.records if r.seq != 2)
    result = publishing.verify_package(
        publishing.ExportPackage(3, missing), credentials[-1].chain_value
    )
    assert result.valid is False
    assert result.first_broken_id == 2

    # 删除末端记录：断裂点为 3，包内没有末端链值可回报
    missing_tail = tuple(r for r in package.records if r.seq != 3)
    result = publishing.verify_package(
        publishing.ExportPackage(3, missing_tail), credentials[-1].chain_value
    )
    assert result.first_broken_id == 3
    assert result.server_chain_value is None

    # 空包：断裂点为 1
    result = publishing.verify_package(
        publishing.ExportPackage(3, ()), credentials[-1].chain_value
    )
    assert result.first_broken_id == 1
    assert result.server_chain_value is None


@pytest.mark.parametrize("tamper_seq", [1, 2, 3])
def test_verify_package_detects_tampered_content(db: str, tamper_seq: int) -> None:
    credentials = _publish_n(db, 3)
    package = publishing.export_package_through(3, path=db)
    assert package is not None
    records = [
        publishing.PackageRecord(
            seq=r.seq,
            masked_text="被篡改" if r.seq == tamper_seq else r.masked_text,
            ranges=r.ranges,
            text_digest=r.text_digest,
            chain_value=r.chain_value,
        )
        for r in package.records
    ]
    result = publishing.verify_package(
        publishing.ExportPackage(3, tuple(records)), credentials[-1].chain_value
    )
    assert result.first_broken_id == tamper_seq
    assert result.valid is False


def test_verify_package_detects_tampered_chain_value(db: str) -> None:
    credentials = _publish_n(db, 2)
    package = publishing.export_package_through(2, path=db)
    assert package is not None
    records = list(package.records)
    records[1] = publishing.PackageRecord(
        records[1].seq,
        records[1].masked_text,
        records[1].ranges,
        records[1].text_digest,
        "f" * 64,
    )
    result = publishing.verify_package(
        publishing.ExportPackage(2, tuple(records)), credentials[-1].chain_value
    )
    assert result.first_broken_id == 2


def test_verify_package_detects_reordered_ranges(db: str) -> None:
    _publish_n(db, 1)
    tail = publishing.publish_credential(
        "██████",
        [(0, 3), (3, 6)],
        publishing.salted_text_digest("abcdef"),
        path=db,
    )
    package = publishing.export_package_through(2, path=db)
    assert package is not None
    records = list(package.records)
    tampered = records[-1]
    records[-1] = publishing.PackageRecord(
        tampered.seq,
        tampered.masked_text,
        ((3, 6), (0, 3)),  # 区间顺序被改动
        tampered.text_digest,
        tampered.chain_value,
    )
    result = publishing.verify_package(
        publishing.ExportPackage(2, tuple(records)), tail.chain_value
    )
    assert result.first_broken_id == 2


def test_verify_package_detects_duplicate_seq(db: str) -> None:
    credentials = _publish_n(db, 3)
    package = publishing.export_package_through(3, path=db)
    assert package is not None
    duplicated = (package.records[0],) + package.records
    result = publishing.verify_package(
        publishing.ExportPackage(3, duplicated), credentials[-1].chain_value
    )
    assert result.valid is False
    assert result.first_broken_id == 1


def test_verify_package_accepts_shuffled_order(db: str) -> None:
    credentials = _publish_n(db, 3)
    package = publishing.export_package_through(3, path=db)
    assert package is not None
    shuffled = publishing.ExportPackage(
        3, tuple(reversed(package.records))
    )
    result = publishing.verify_package(shuffled, credentials[-1].chain_value)
    assert result.valid is True
    assert result.first_broken_id is None


def test_init_db_is_idempotent(db: str) -> None:
    publishing.init_db(db)
    publishing.init_db(db)
    # 表存在且可写
    cred = publishing.publish_credential(
        "█", [(0, 1)], publishing.salted_text_digest("a"), path=db
    )
    assert cred.seq == 1
