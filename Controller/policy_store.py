"""Transactional, append-only local policy snapshots; read commands open SQLite read-only."""

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3

from firewall_policy import canonical_bytes, normalize, parse_json, sha256


SCHEMA_VERSION = 1
DDL = """
CREATE TABLE snapshots (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL, site TEXT NOT NULL, device TEXT NOT NULL, context TEXT NOT NULL,
  vendor TEXT NOT NULL, revision TEXT NOT NULL, collected_at TEXT NOT NULL,
  created_at TEXT NOT NULL, rule_count INTEGER NOT NULL, object_count INTEGER NOT NULL,
  normalized BLOB NOT NULL
);
CREATE INDEX snapshot_scope ON snapshots(tenant, site, device, context, created_at);
CREATE TABLE raw_exports (sha256 TEXT PRIMARY KEY, content BLOB NOT NULL);
CREATE TABLE imports (
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
  raw_sha256 TEXT NOT NULL REFERENCES raw_exports(sha256),
  imported_at TEXT NOT NULL
);
CREATE INDEX import_snapshot ON imports(snapshot_id);
"""


class PolicyStore:
    def __init__(self, path, writable=False):
        self.path = Path(path).resolve()
        self.writable = writable
        if writable:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Exclusive creation avoids accidentally replacing an existing database.
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            self.connection = sqlite3.connect(self.path, timeout=5)
        else:
            # mode=ro fails for a missing path and cannot create or modify a database.
            self.connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0 and writable:
                if self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                    raise ValueError("Refusing to initialize an unrelated database")
                self.connection.executescript("BEGIN IMMEDIATE;\n" + DDL + "\nPRAGMA user_version=1;\nCOMMIT;")
            elif version != SCHEMA_VERSION:
                raise ValueError("Unsupported policy database version")
            # Version numbers alone do not identify an unrelated SQLite file's tables.
            for statement in (
                "SELECT id,tenant,site,device,context,vendor,revision,collected_at,created_at,rule_count,object_count,normalized FROM snapshots LIMIT 0",
                "SELECT sha256,content FROM raw_exports LIMIT 0",
                "SELECT id,snapshot_id,raw_sha256,imported_at FROM imports LIMIT 0",
            ):
                self.connection.execute(statement)
            if not writable:
                self.connection.execute("PRAGMA query_only=ON")
        except Exception:
            self.connection.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.connection.close()

    def import_snapshot(self, raw, policy):
        if not self.writable:
            raise ValueError("This store was opened read-only")
        # Re-derive the model from raw bytes so callers cannot pair unrelated evidence and policy.
        verified = normalize(parse_json(raw))
        if canonical_bytes(verified) != canonical_bytes(policy):
            raise ValueError("Raw input and normalized policy disagree")
        payload = canonical_bytes(verified)
        snapshot_id, raw_hash = sha256(payload), sha256(raw)
        imported_at = datetime.now(timezone.utc).isoformat()
        with self.connection:
            # Serialize the existence check and inserts, including concurrent imports.
            self.connection.execute("BEGIN IMMEDIATE")
            if self.path.stat().st_size + len(raw) + len(payload) + 16384 > 256 * 1024**2:
                raise ValueError("Policy store would exceed the 256 MiB pilot budget; archive the closed database")
            existing = self.connection.execute("SELECT normalized FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if existing is not None and bytes(existing[0]) != payload:
                raise ValueError("Existing snapshot content does not match its identity")
            prior_raw = self.connection.execute("SELECT content FROM raw_exports WHERE sha256=?", (raw_hash,)).fetchone()
            if prior_raw is not None and bytes(prior_raw[0]) != raw:
                raise ValueError("Existing raw export integrity check failed")
            self.connection.execute("INSERT OR IGNORE INTO raw_exports(sha256,content) VALUES (?,?)", (raw_hash, raw))
            self.connection.execute("""INSERT OR IGNORE INTO snapshots
                (id,tenant,site,device,context,vendor,revision,collected_at,created_at,rule_count,object_count,normalized)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (snapshot_id, verified["tenant"], verified["site"], verified["device"], verified["context"],
                 verified["vendor"], verified["policy_revision"], verified["collected_at"], imported_at,
                 len(verified["rules"]), len(verified["objects"]), payload))
            self.connection.execute("INSERT INTO imports(snapshot_id,raw_sha256,imported_at) VALUES (?,?,?)",
                                    (snapshot_id, raw_hash, imported_at))
        return {"snapshot_id": snapshot_id, "raw_sha256": raw_hash, "created": existing is None,
                "source_kind": "operator_description", "enforcement": "NOT_ATTEMPTED"}

    def list_snapshots(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Snapshot limit must be 1..200")
        fields = "id,tenant,site,device,context,vendor,revision,collected_at,created_at,rule_count,object_count"
        rows = self.connection.execute(f"SELECT {fields} FROM snapshots ORDER BY created_at DESC,id LIMIT ?", (limit,))
        total = self.connection.execute("SELECT count(*) FROM snapshots").fetchone()[0]
        return {"snapshots": [dict(row) for row in rows], "total": total, "truncated": total > limit}

    def get_snapshot(self, snapshot_id):
        if not isinstance(snapshot_id, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot_id):
            raise ValueError("Snapshot ID must be its lowercase SHA-256")
        row = self.connection.execute("SELECT normalized FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if row is None:
            raise KeyError("Unknown snapshot")
        raw = bytes(row[0])
        if sha256(raw) != snapshot_id:
            raise ValueError("Stored snapshot integrity check failed")
        return normalize(parse_json(raw))

    def provenance(self, snapshot_id):
        self.get_snapshot(snapshot_id)
        rows = self.connection.execute("""SELECT i.id,i.imported_at,i.raw_sha256,r.content
            FROM imports i JOIN raw_exports r ON r.sha256=i.raw_sha256
            WHERE i.snapshot_id=? ORDER BY i.id DESC LIMIT 20""", (snapshot_id,))
        imports = []
        for row in rows:
            if sha256(bytes(row["content"])) != row["raw_sha256"]:
                raise ValueError("Stored raw export integrity check failed")
            imports.append({"id": row["id"], "imported_at": row["imported_at"], "raw_sha256": row["raw_sha256"]})
        count = self.connection.execute("SELECT count(*) FROM imports WHERE snapshot_id=?", (snapshot_id,)).fetchone()[0]
        return {"imports": imports, "total_imports": count, "truncated": count > len(imports),
                "integrity": "returned hashes verified, not source authentication"}
