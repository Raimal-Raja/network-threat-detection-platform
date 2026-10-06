"""SQLite cases and append-only analyst feedback for simulated investigations."""
import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class Conflict(ValueError):
    pass


class MissingCase(LookupError):
    pass


def dumps(value):
    return json.dumps(value, sort_keys=True, allow_nan=False)


class CaseStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, event_id TEXT NOT NULL,
                    bundle_sha256 TEXT NOT NULL, request_sha256 TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL, flow_json TEXT NOT NULL,
                    prediction_json TEXT NOT NULL, explanation_json TEXT NOT NULL,
                    alert INTEGER NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(event_id, bundle_sha256));
                CREATE TABLE IF NOT EXISTS feedback (
                    case_id TEXT NOT NULL REFERENCES cases(id),
                    revision INTEGER NOT NULL, reviewer TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK(verdict IN ('suspicious','benign','uncertain')),
                    note TEXT NOT NULL, created_at_utc TEXT NOT NULL,
                    PRIMARY KEY(case_id, revision));
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, case_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if row is None:
                raise MissingCase("case not found")
            history = [dict(r) for r in db.execute(
                "SELECT revision,reviewer,verdict,note,created_at_utc FROM feedback WHERE case_id=? ORDER BY revision",
                (case_id,))]
        return {"id": row["id"], "event_id": row["event_id"],
                "created_at_utc": row["created_at_utc"], "revision": row["revision"],
                "flow": json.loads(row["flow_json"]),
                "flow_display": {key: str(value) for key, value in json.loads(row["flow_json"]).items()},
                "prediction": json.loads(row["prediction_json"]),
                "explanation": json.loads(row["explanation_json"]), "feedback": history,
                "review": history[-1]["verdict"] if history else "unreviewed",
                "simulated": True, "production_ready": False}

    def save(self, event_id, flow, prediction, explanation):
        request_sha = hashlib.sha256(dumps(flow).encode()).hexdigest()
        identity = prediction["bundle_sha256"]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT id,request_sha256 FROM cases WHERE event_id=? AND bundle_sha256=?",
                                  (event_id, identity)).fetchone()
            if existing:
                if existing["request_sha256"] != request_sha:
                    raise Conflict("event ID already exists with different measurements")
                case_id = existing["id"]
            else:
                case_id = uuid.uuid4().hex
                db.execute("INSERT INTO cases(id,event_id,bundle_sha256,request_sha256,created_at_utc,flow_json,prediction_json,explanation_json,alert) VALUES(?,?,?,?,?,?,?,?,?)",
                           (case_id, event_id, identity, request_sha, datetime.now(timezone.utc).isoformat(),
                            dumps(flow), dumps(prediction), dumps(explanation), int(prediction["alert"])))
        return self.get(case_id)

    def list(self, limit=50, offset=0, alert_only=False, review="all"):
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
            raise ValueError("invalid pagination")
        if review not in ("all", "unreviewed", "suspicious", "benign", "uncertain"):
            raise ValueError("invalid review filter")
        condition = """(?=0 OR alert=1) AND
            (?='all' OR COALESCE((SELECT verdict FROM feedback f WHERE f.case_id=cases.id
                ORDER BY revision DESC LIMIT 1),'unreviewed')=?)"""
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM cases WHERE " + condition,
                               (int(alert_only), review, review)).fetchone()[0]
            rows = db.execute(
                "SELECT id,event_id,created_at_utc,revision,prediction_json,COALESCE((SELECT verdict FROM feedback f WHERE f.case_id=cases.id ORDER BY revision DESC LIMIT 1),\'unreviewed\') AS review FROM cases WHERE " + condition + " ORDER BY created_at_utc DESC,id DESC LIMIT ? OFFSET ?",
                (int(alert_only), review, review, limit, offset)).fetchall()
            summaries = [{"id": r["id"], "event_id": r["event_id"], "created_at_utc": r["created_at_utc"],
                          "revision": r["revision"], "prediction": json.loads(r["prediction_json"]),
                          "review": r["review"]} for r in rows]
        return {"cases": summaries, "total": total,
                "limit": limit, "offset": offset, "simulated": True, "production_ready": False}

    def feedback(self, case_id, expected_revision, reviewer, verdict, note):
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("invalid review revision")
        if verdict not in ("suspicious", "benign", "uncertain"):
            raise ValueError("invalid verdict")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT revision FROM cases WHERE id=?", (case_id,)).fetchone()
            if row is None:
                raise MissingCase("case not found")
            if row["revision"] != expected_revision:
                raise Conflict("review changed; reload before submitting")
            revision = expected_revision + 1
            db.execute("INSERT INTO feedback VALUES(?,?,?,?,?,?)",
                       (case_id, revision, reviewer, verdict, note, datetime.now(timezone.utc).isoformat()))
            db.execute("UPDATE cases SET revision=? WHERE id=?", (revision, case_id))
        return self.get(case_id)
