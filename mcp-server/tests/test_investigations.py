"""Unit tests for the read-only SQL guard, the catalog, and the window predicate.

These don't touch AWS — they exercise the pure logic that decides what gets executed.
"""

from audit_planes_mcp import investigations as inv


def test_rejects_mutations():
    for bad in [
        "DROP TABLE cloudtrail_logs",
        "delete from vpc_flow_logs",
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET x = 1",
        "ALTER TABLE t ADD COLUMN c int",
        "MSCK REPAIR TABLE t",
        "CREATE TABLE t AS SELECT 1",
    ]:
        assert inv._is_read_only(bad) is False, bad


def test_allows_reads():
    for good in [
        "SELECT * FROM cloudtrail_logs LIMIT 1",
        "  with x as (select 1) select * from x",
        "-- a comment\nSELECT count(*) FROM t",
        "SHOW TABLES",
        "DESCRIBE cloudtrail_logs",
    ]:
        assert inv._is_read_only(good) is True, good


def test_rejects_multi_statement():
    assert inv._is_read_only("SELECT 1; DROP TABLE t") is False


def test_empty_is_not_read_only():
    assert inv._is_read_only("   \n  ") is False
    assert inv._is_read_only("-- only a comment") is False


def test_window_predicate_uses_partition_and_timestamp():
    pred = inv._window_predicate("cloudtrail", 24)
    assert '"date" >=' in pred
    assert "from_iso8601_timestamp(eventtime)" in pred
    assert "interval '24' hour" in pred

    flow = inv._window_predicate("vpc_flow", 6)
    assert "from_unixtime(start)" in flow
    assert "interval '6' hour" in flow


def test_catalog_shape():
    catalog = inv.list_catalog()
    ids = {c["check"] for c in catalog}
    # Every plane is represented.
    assert {"api.enumeration", "network.top-talkers", "dns.tunnelling",
            "web.alb-status-by-ip", "storage.reads-by-principal"} <= ids
    # Checks that need a filter declare it.
    needs = {c["check"]: c["needs"] for c in catalog}
    assert needs["api.principal-timeline"] == ["principal"]
    assert needs["storage.reads-by-principal"] == ["bucket"]


def test_unknown_check_is_reported():
    res = inv.run_investigation("nope.does-not-exist")
    assert res["ok"] is False
    assert "available" in res


def test_missing_required_filter_is_reported():
    res = inv.run_investigation("storage.reads-by-principal", filters={})
    assert res["ok"] is False
    assert "bucket" in res["error"]
