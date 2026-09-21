"""Streaming CSV and read-only Excel regression tests without FUSE."""
import base64
import csv
import errno
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins.tabular import plugin
from openkapsel.rpc_plugins.tabular.csv_stream import CSVStream, csv_options, _encode_cursor, _digest
from openkapsel.rpc_plugins.tabular.excel import available_formats
from openkapsel.rpc_plugins._data import Snapshot, identity
from tests.test_structured_rpc import Task


def workbook_bytes(*, dimension="A1:C4", malicious=False):
    """Tiny OOXML fixture with numeric values, a cached formula and text."""
    output = io.BytesIO()
    files = {
        "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        "_rels/.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml": f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="{dimension}"/><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>id</t></is></c><c r="B1" t="inlineStr"><is><t>value</t></is></c><c r="C1" t="inlineStr"><is><t>name</t></is></c></row>'
            '<row r="2"><c r="A2"><v>1</v></c><c r="B2"><f>1+2</f><v>3</v></c><c r="C2" t="inlineStr"><is><t>first</t></is></c></row>'
            '<row r="3"><c r="A3"><v>2</v></c><c r="B3"><v>5</v></c><c r="C3" t="inlineStr"><is><t>second</t></is></c></row>'
            '<row r="4"><c r="A4"><v>3</v></c><c r="B4"><v>8</v></c><c r="C4" t="inlineStr"><is><t>last</t></is></c></row>'
            '</sheetData></worksheet>',
    }
    if malicious:
        files["xl/workbook.xml"] = '<!DOCTYPE workbook [<!ENTITY xxe SYSTEM "file:///not-to-be-read">]>' + files["xl/workbook.xml"].replace('name="Data"', 'name="&xxe;"')
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, text in files.items():
            bundle.writestr(name, text)
    return output.getvalue()


class TabularTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        cls = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            cls = WindowsClientFiles
        self.files = cls(self.root, writable=False)
    def tearDown(self):
        self.files.close()
        self.temp.cleanup()
    def source(self, text='id,text\n1,a\n2,b\n3,c\n', name="data.csv", encoding="utf-8"):
        (self.root / name).write_bytes(text.encode(encoding))
        return name
    def call(self, operation, args, expected=200, task=None):
        if operation == "scan":
            value = plugin.dispatch_task(self.files, operation, args, task or Task())
        else:
            value = self.files.dispatch("tabular_" + operation, args)
        self.assertEqual(expected, value["status"], value)
        return value.get("body", value.get("error"))
    def pages(self, args):
        rows, calls = [], 0
        while True:
            body = self.call("read", args)
            rows.extend(body["rows"])
            calls += 1
            self.assertLess(calls, 100)
            if body["eof"]:
                self.assertIsNone(body["next_cursor"])
                return rows
            self.assertTrue(body["next_cursor"])
            args = dict(args, cursor=body["next_cursor"])

    def test_multiline_unicode_bom_and_line_endings_resume_without_loss(self):
        for newline in ("\n", "\r\n", "\r"):
            text = newline.join(['id,text', '1,"a' + newline + 'b"', '2,"quoted ""value"""', '3,\u4e2d\u6587', '4,last'])
            self.source('\ufeff' + text)
            rows = self.pages({"path": "data.csv", "limit": 1})
            self.assertEqual([["1", "a" + newline + "b"], ["2", 'quoted "value"'], ["3", '\u4e2d\u6587'], ["4", "last"]], rows)

    def test_projection_filters_and_empty_page_are_not_eof(self):
        self.source()
        args = {"path": "data.csv", "where": [{"column": "id", "op": "gt", "value": 2}],
                "columns": ["text"], "scan_rows": 1}
        first = self.call("read", args)
        self.assertEqual([], first["rows"])
        self.assertFalse(first["eof"])
        self.assertEqual("scan_rows", first["stop_reason"])
        self.assertEqual([["c"]], self.pages(dict(args, cursor=first["next_cursor"])))
        self.assertEqual([["2", "b"]], self.pages({"path": "data.csv", "where": [{"column": "text", "op": "contains", "value": "b"}]}))

    def test_output_budget_rewinds_unreturned_record(self):
        self.source('id,text\n' + ''.join(f'{i},' + ('x' * 400) + '\n' for i in range(8)))
        rows = self.pages({"path": "data.csv", "limit": 100, "max_result_bytes": 1024})
        self.assertEqual([str(i) for i in range(8)], [row[0] for row in rows])
        self.source('id,text\n1,' + 'x' * 2000 + '\n')
        self.call("read", {"path": "data.csv", "max_result_bytes": 1024}, 413)
        self.assertEqual([["1"]], self.call("read", {"path": "data.csv", "max_result_bytes": 1024, "columns": [0]})["rows"])

    def test_duplicate_headers_ragged_rows_and_no_header(self):
        self.source('a,a,b\n1,2,3,4\n5\n\n')
        self.call("read", {"path": "data.csv", "columns": ["a"]}, 400)
        body = self.call("read", {"path": "data.csv"})
        self.assertEqual([["1", "2", "3", "4"], ["5"], []], body["rows"])
        self.assertEqual(3, body["ragged_rows"])
        self.assertEqual([["2"], [None], [None]], self.call("read", {"path": "data.csv", "columns": [1]})["rows"])
        self.source('10,20\n30,40\n')
        self.assertEqual([["10", "20"], ["30", "40"]], self.pages({"path": "data.csv", "csv": {"header": False}, "limit": 1}))

    def test_encoding_and_tsv_are_explicit(self):
        self.source('name;value\n\u4e2d\u6587;1\n', encoding="gbk")
        self.call("read", {"path": "data.csv"}, 415)
        body = self.call("read", {"path": "data.csv", "csv": {"encoding": "gbk", "delimiter": ";"}})
        self.assertEqual('\u4e2d\u6587', body["rows"][0][0])
        self.source('a\tb\n1\t2\n', name="data.tsv")
        self.assertEqual([["1", "2"]], self.call("read", {"path": "data.tsv"})["rows"])

    def test_cursor_rejects_tampering_expiration_path_dialect_and_changed_file(self):
        self.source()
        first = self.call("read", {"path": "data.csv", "limit": 1})
        cursor = first["next_cursor"]
        for bad in ('garbage', cursor[:20] + ('A' if cursor[20] != 'A' else 'B') + cursor[21:]):
            self.call("read", {"path": "data.csv", "cursor": bad}, 409)
        self.source(name="other.csv")
        self.call("read", {"path": "other.csv", "cursor": cursor}, 409)
        self.call("read", {"path": "data.csv", "cursor": cursor, "csv": {"delimiter": ";"}}, 409)
        with patch("openkapsel.rpc_plugins.tabular.csv_stream.time.time", return_value=10**11):
            self.call("read", {"path": "data.csv", "cursor": cursor}, 409)
        self.files.close()  # Network disconnect closes file handles, not cursor key.
        self.assertEqual([["2", "b"], ["3", "c"]], self.call("read", {"path": "data.csv", "cursor": cursor})["rows"])
        with (self.root / "data.csv").open("ab") as stream:
            stream.write(b'4,d\n')
        self.call("read", {"path": "data.csv", "cursor": cursor}, 409)

    def test_file_change_during_read_discards_result(self):
        self.source()
        original = CSVStream.next_row
        changed = False
        def replace(stream):
            nonlocal changed
            value = original(stream)
            if not changed:
                changed = True
                with (self.root / "data.csv").open("ab") as out:
                    out.write(b'4,d\n')
            return value
        with patch.object(CSVStream, "next_row", replace):
            self.call("read", {"path": "data.csv"}, 409)

    def test_inspect_is_bounded_and_does_not_count_whole_file(self):
        self.source('id,text\n' + '1,a\n' * 10000)
        calls = 0
        original = CSVStream.next_row
        def counted(stream):
            nonlocal calls
            calls += 1
            return original(stream)
        with patch.object(CSVStream, "next_row", counted):
            value = self.call("inspect", {"path": "data.csv", "sample_rows": 2})
        self.assertEqual(2, calls)
        self.assertIsNone(value["total_rows"])
        self.assertTrue(value["sample_is_not_full_scan"])

    def test_count_segments_and_numeric_aggregation(self):
        self.source('group,amount\na,1.2\nb,2.3\na,3.4\na,not-number\nb,\n')
        scan = {"path": "data.csv", "mode": "aggregate", "group_by": ["group"], "scan_rows": 2,
                "metrics": [{"name": "total", "op": "sum", "column": "amount"},
                            {"name": "average", "op": "mean", "column": "amount"}, {"name": "count", "op": "count"}]}
        rows = 0
        sums = {}
        while True:
            result = self.call("scan", scan)
            self.assertEqual("segment", result["result_scope"])
            self.assertEqual(rows, result["start_row_exclusive"])
            rows += result["rows_scanned"]
            for group in result["groups"]:
                amount = group["metrics"]["total"]["value"]
                sums[group["key"][0]] = sums.get(group["key"][0], Decimal(0)) + (Decimal(amount) if amount is not None else 0)
            if result["complete"]:
                break
            scan["cursor"] = result["next_cursor"]
        self.assertEqual(5, rows)
        self.assertEqual({"a": Decimal('4.6'), "b": Decimal('2.3')}, sums)
        whole = self.call("scan", {"path": "data.csv", "mode": "aggregate", "group_by": ["group"], "metrics": scan["metrics"]})
        a = next(g for g in whole["groups"] if g["key"] == ["a"])
        self.assertEqual('2.3', a["metrics"]["average"]["value"])
        self.assertEqual('4.6', a["metrics"]["average"]["sum"])
        self.assertEqual(1, a["metrics"]["total"]["invalid"])
        self.assertEqual(5, self.call("scan", {"path": "data.csv"})["matched_rows"])
        self.assertEqual(3, self.call("scan", {"path": "data.csv", "where": [{"column": "group", "op": "eq", "value": "a"}]})["matched_rows"])

    def test_numeric_sum_preserves_small_terms_after_large_cancellation(self):
        self.source('amount\n1e128\n1e-128\n-1e128\n')
        body = self.call("scan", {"path": "data.csv", "mode": "aggregate", "metrics": [
            {"op": "sum", "column": "amount", "name": "total"},
            {"op": "mean", "column": "amount", "name": "average"},
        ]})
        metrics = body["groups"][0]["metrics"]
        self.assertEqual(Decimal('1e-128'), Decimal(metrics["total"]["value"]))
        self.assertEqual(Decimal('1e-128'), Decimal(metrics["average"]["sum"]))
        self.assertEqual(3, metrics["average"]["count"])

    def test_text_filters_reject_non_string_operands(self):
        self.source()
        for op in ("contains", "starts_with"):
            for value in (1, 1.5, True, None):
                with self.subTest(op=op, value=value):
                    error = self.call("read", {"path": "data.csv", "where": [
                        {"column": "text", "op": op, "value": value},
                    ]}, 400)
                    self.assertEqual("tabular_filter_value", error["code"])

    def test_scan_cancellation_limits_and_readonly_side_effects(self):
        self.source()
        before = (self.root / "data.csv").read_bytes()
        self.call("scan", {"path": "data.csv", "mode": "aggregate", "group_by": ["text"], "max_groups": 1,
                  "metrics": [{"name": "n", "op": "count"}]}, 413)
        with self.assertRaises(OSError) as caught:
            self.call("scan", {"path": "data.csv"}, task=Task(True))
        self.assertEqual(errno.ECANCELED, caught.exception.errno)
        self.assertEqual(before, (self.root / "data.csv").read_bytes())
        self.assertEqual(["data.csv"], sorted(p.name for p in self.root.iterdir()))
        self.assertTrue(all(spec["write"] is False for spec in plugin.operations.values()))
        self.assertTrue(all(spec["execution"] == "sync" for name, spec in plugin.operations.items() if name != "scan"))

    def test_malformed_fields_and_dialect_limits(self):
        for raw in ('a,b\n1,"not-closed\n', 'a,b\n1,' + 'x' * (csv.field_size_limit() + 1)):
            self.source(raw)
            self.call("read", {"path": "data.csv"}, 422)
        self.source('a,b\n' + ('x,' * 600000) + '\n')
        self.call("read", {"path": "data.csv"}, 413)
        self.source()
        for args in ({"offset": 1000000}, {"csv": {"encoding": "utf-16"}}, {"csv": {"delimiter": "\n"}}, {"columns": [0, 0]}):
            self.call("read", dict(args, path="data.csv"), 400)
        self.call("read", {"path": ".openkapsel/private.csv"}, 403)

    @unittest.skipIf(os.name == "nt", "POSIX sparse seek fixture; do not allocate 10 GiB on Windows")
    def test_large_csv_headers_and_authenticated_seek_cookies_above_2_and_10_gib(self):
        # Sparse holes are NOT a throughput/full-valid-CSV test. They verify
        # 64-bit checkpoint handling and no scan of the prefix when resuming.
        for boundary in (2 * 1024**3, 10 * 1024**3):
            path = self.root / "large.csv"
            with path.open("wb") as stream:
                stream.write(b'id,text\n1,first\n')
                stream.seek(boundary)
                stream.write(b'2,near-end\n3,last\n')
            info = self.call("inspect", {"path": "large.csv", "sample_rows": 1})
            self.assertGreater(info["file_size_bytes"], boundary)
            options = csv_options({})
            details = path.stat()
            cursor = _encode_cursor({"v": 1, "scope": _digest(str(path.resolve())), "identity": _digest(identity(details)),
                                     "dialect": _digest(options), "position": str(boundary), "row": 1, "expires": 10**11})
            original = CSVStream._parse_row
            calls = 0
            def count(stream):
                nonlocal calls
                calls += 1
                return original(stream)
            with patch.object(CSVStream, "_parse_row", count):
                rows = self.pages({"path": "large.csv", "cursor": cursor, "limit": 1})
            self.assertEqual([["2", "near-end"], ["3", "last"]], rows)
            self.assertLessEqual(calls, 6)
            path.unlink()

    @unittest.skipUnless("xlsx" in available_formats(), "optional Excel dependencies")
    def test_excel_cached_formula_modes_cursor_and_misreported_dimensions(self):
        for dimension in ("A1:C4", "A1:A1"):
            (self.root / "book.xlsx").write_bytes(workbook_bytes(dimension=dimension))
            before = (self.root / "book.xlsx").read_bytes()
            body = self.call("inspect", {"path": "book.xlsx"})
            self.assertEqual("Data", body["sheets"][0]["name"])
            self.assertFalse(body["formulas_recalculated"])
            self.assertEqual([[1, 3, "first"], [2, 5, "second"], [3, 8, "last"]], self.pages({"path": "book.xlsx", "limit": 1}))
            formula = self.call("read", {"path": "book.xlsx", "excel": {"value_mode": "formula"}, "limit": 1})
            self.assertEqual("=1+2", formula["rows"][0][1])
            first = self.call("read", {"path": "book.xlsx", "excel": {"start_row": 3}, "limit": 1})
            self.assertEqual([[2, 5, "second"]], first["rows"])
            rest = self.call("read", {"path": "book.xlsx", "cursor": first["next_cursor"]})
            self.assertEqual([[3, 8, "last"]], rest["rows"])
            count = self.call("scan", {"path": "book.xlsx"})
            self.assertEqual(3, count["matched_rows"])
            self.assertEqual(before, (self.root / "book.xlsx").read_bytes())

    @unittest.skipUnless("xls" in available_formats(), "optional legacy Excel dependency")
    def test_legacy_xls_values_dates_and_readonly_contract(self):
        raw = (Path(__file__).parent / "fixtures/tabular-readonly.xls").read_bytes()
        path = self.root / "book.xls"
        path.write_bytes(raw)
        body = self.call("read", {"path": "book.xls"})
        self.assertEqual([1.0, 2.5, "first", True, "2026-09-21T00:00:00"], body["rows"][0])
        self.assertEqual([2.0, 5.25, "second", False, "2026-09-21T00:00:00"], body["rows"][1])
        scan = self.call("scan", {"path": "book.xls", "mode": "aggregate",
                          "metrics": [{"op": "sum", "column": "amount", "name": "total"}]})
        self.assertEqual("7.75", scan["groups"][0]["metrics"]["total"]["value"])
        self.call("read", {"path": "book.xls", "excel": {"value_mode": "formula"}}, 415)
        self.assertEqual(raw, path.read_bytes())

    @unittest.skipUnless("xlsx" in available_formats(), "optional Excel dependencies")
    def test_excel_rejects_unknown_sheet_entities_and_changed_file(self):
        path = self.root / "book.xlsx"
        path.write_bytes(workbook_bytes())
        self.call("read", {"path": "book.xlsx", "excel": {"sheet": "Missing"}}, 404)
        body = self.call("read", {"path": "book.xlsx", "limit": 1})
        path.write_bytes(workbook_bytes(dimension="A1:A1"))
        self.call("read", {"path": "book.xlsx", "cursor": body["next_cursor"]}, 409)
        path.write_bytes(workbook_bytes(malicious=True))
        self.call("read", {"path": "book.xlsx"}, 422)


if __name__ == "__main__":
    unittest.main()
