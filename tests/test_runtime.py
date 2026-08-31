from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path

from sqlalchemy import text

import openkapsel_runtime
from openkapsel_runtime import database


class RuntimeSurfaceTests(unittest.TestCase):
    def test_runtime_exposes_only_database_helpers(self) -> None:
        self.assertEqual(["database"], openkapsel_runtime.__all__)
        self.assertFalse(hasattr(openkapsel_runtime, "create_app"))
        self.assertFalse(hasattr(openkapsel_runtime, "current_user"))

    def test_fastapi_multipart_routes_are_available(self) -> None:
        from fastapi import FastAPI, File, Form, UploadFile

        app = FastAPI()

        @app.post("/upload")
        async def upload(
            uploaded: UploadFile = File(...),
            label: str = Form(...),
        ) -> dict[str, str]:
            return {"filename": uploaded.filename or "", "label": label}

        self.assertTrue(any(route.path == "/upload" for route in app.routes))

    def test_template_and_http_client_libraries_are_available(self) -> None:
        import httpx
        from fastapi.templating import Jinja2Templates

        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "hello.html"
            template.write_text("Hello, {{ name }}!", encoding="utf-8")
            templates = Jinja2Templates(directory=directory)
            self.assertEqual(
                "Hello, OpenKapsel!",
                templates.get_template("hello.html").render(name="OpenKapsel"),
            )
        self.assertTrue(hasattr(httpx, "AsyncClient"))


class DatabaseRuntimeTests(unittest.TestCase):
    def test_engine_and_transactional_session_match_discovery_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous_workspace = os.environ.get("OPENKAPSEL_WORKSPACE")
            os.environ["OPENKAPSEL_WORKSPACE"] = str(root)
            database_id = "test_" + uuid.uuid4().hex
            value = database.engine(database_id)
            try:
                storage = root / ".openkapsel" / "sql"
                self.assertTrue(storage.is_dir())
                self.assertEqual(0o700, storage.stat().st_mode & 0o777)
                self.assertIs(value, database.engine(database_id))
                self.assertEqual(storage / f"{database_id}.sqlite3", Path(value.url.database))
                with value.connect() as connection:
                    self.assertEqual(1, connection.exec_driver_sql("PRAGMA foreign_keys").scalar())
                    self.assertEqual(5000, connection.exec_driver_sql("PRAGMA busy_timeout").scalar())
                    self.assertEqual("wal", connection.exec_driver_sql("PRAGMA journal_mode").scalar())
                with value.begin() as connection:
                    connection.execute(text("CREATE TABLE items (value TEXT NOT NULL)"))

                with database.session(database_id) as session:
                    session.execute(text("INSERT INTO items (value) VALUES ('committed')"))
                with value.connect() as connection:
                    self.assertEqual(1, connection.execute(text("SELECT count(*) FROM items")).scalar())

                with self.assertRaisesRegex(RuntimeError, "rollback test"):
                    with database.session(database_id) as session:
                        session.execute(text("INSERT INTO items (value) VALUES ('rolled-back')"))
                        raise RuntimeError("rollback test")
                with value.connect() as connection:
                    self.assertEqual(1, connection.execute(text("SELECT count(*) FROM items")).scalar())

                with self.assertRaisesRegex(ValueError, "database id"):
                    database.engine("../outside")
            finally:
                value.dispose()
                database._engines.pop(database_id, None)
                if previous_workspace is None:
                    os.environ.pop("OPENKAPSEL_WORKSPACE", None)
                else:
                    os.environ["OPENKAPSEL_WORKSPACE"] = previous_workspace
if __name__ == "__main__":
    unittest.main()
