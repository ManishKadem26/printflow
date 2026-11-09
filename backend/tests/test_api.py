"""Backend tests with in-memory fakes for Supabase and R2 (no network, no real data).

Run from the backend folder:
    pip install pytest httpx
    python -m pytest tests -q
"""

import copy
import hashlib
import hmac
import importlib
import os
import sys

import pytest

OWNER_PIN = "908172"
WORKER_PIN = "445566"
RZP_SECRET = "test_secret"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeQuery:
    def __init__(self, db, table):
        self.db, self.table = db, table
        self.filters, self.op, self.payload = [], "select", None
        self._limit, self._order = None, None

    def select(self, _cols="*"):
        self.op = "select"
        return self

    def insert(self, row):
        self.op, self.payload = "insert", row
        return self

    def update(self, data):
        self.op, self.payload = "update", data
        return self

    def upsert(self, row):
        self.op, self.payload = "upsert", row
        return self

    def eq(self, col, val):
        self.filters.append(lambda r: r.get(col) == val)
        return self

    def neq(self, col, val):
        self.filters.append(lambda r: r.get(col) != val)
        return self

    def order(self, col, desc=False):
        self._order = (col, desc)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        rows = self.db.setdefault(self.table, [])
        match = [r for r in rows if all(f(r) for f in self.filters)]
        if self.op == "insert":
            if any(r["id"] == self.payload["id"] for r in rows):
                raise Exception("duplicate key value violates unique constraint")
            row = {"created_at": "2026-11-09T10:00:00+00:00", "rejection_reason": None, **copy.deepcopy(self.payload)}
            rows.append(row)
            return type("R", (), {"data": [row]})
        if self.op == "update":
            for r in match:
                r.update(copy.deepcopy(self.payload))
            return type("R", (), {"data": match})
        if self.op == "upsert":
            existing = [r for r in rows if r.get("id") == self.payload.get("id")]
            if existing:
                existing[0].update(copy.deepcopy(self.payload))
            else:
                rows.append(copy.deepcopy(self.payload))
            return type("R", (), {"data": [self.payload]})
        if self._order:
            col, desc = self._order
            match = sorted(match, key=lambda r: r.get(col) or "", reverse=desc)
        if self._limit:
            match = match[: self._limit]
        return type("R", (), {"data": copy.deepcopy(match)})


class FakeSupabase:
    def __init__(self):
        self.db = {}

    def table(self, name):
        return FakeQuery(self.db, name)


class FakeS3:
    def __init__(self):
        self.objects = {}

    def head_bucket(self, Bucket):
        return {}

    def head_object(self, Bucket, Key):
        from botocore.exceptions import ClientError
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {}

    def generate_presigned_url(self, ClientMethod, Params, ExpiresIn):
        return f"https://r2.test/{Params['Key']}?sig=x"

    def get_object(self, Bucket, Key):
        import io
        from botocore.exceptions import ClientError
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[Key])}

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def env(monkeypatch):
    for k, v in {
        "R2_ENDPOINT_URL": "https://r2.test", "R2_ACCESS_KEY_ID": "x", "R2_SECRET_ACCESS_KEY": "y",
        "SUPABASE_URL": "https://sb.test", "SUPABASE_SERVICE_KEY": "z",
        "WORKER_SECRET_PIN": WORKER_PIN, "OWNER_SECRET_PIN": OWNER_PIN,
        "RAZORPAY_KEY_ID": "", "RAZORPAY_KEY_SECRET": "", "ALLOWED_ORIGINS": "*",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    fake_db, fake_s3 = FakeSupabase(), FakeS3()
    monkeypatch.setattr("supabase.create_client", lambda *a, **k: fake_db)
    monkeypatch.setattr("boto3.client", lambda *a, **k: fake_s3)
    return fake_db, fake_s3, monkeypatch


def load_app(env, razorpay=False):
    fake_db, fake_s3, monkeypatch = env
    if razorpay:
        monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_abc")
        monkeypatch.setenv("RAZORPAY_KEY_SECRET", RZP_SECRET)
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    from fastapi.testclient import TestClient
    return main, TestClient(main.app), fake_db, fake_s3


def order_body(s3, **overrides):
    key = "orders/" + "a" * 32 + ".pdf"
    s3.objects[key] = b"%PDF-1.4 test"
    body = {
        "customer_name": "Asha", "phone": "+91 98765 43210", "address": "Flat 1, Road 2", "city": "Hyderabad",
        "pincode": "500081", "files": [{"key": key, "name": "notes.pdf", "pages": 12, "size_mb": 1.5}],
        "color_mode": "bw", "sides": "single",
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_missing_secret_fails_fast(env, monkeypatch):
    monkeypatch.delenv("SUPABASE_SERVICE_KEY")
    with pytest.raises(RuntimeError, match="SUPABASE_SERVICE_KEY"):
        load_app(env)


def test_price_is_computed_on_server(env):
    main, client, db, s3 = load_app(env)
    # 12 B&W single-sided pages = 24 + 40 delivery = 64, +5% GST = 67.20
    r = client.post("/api/orders", json=order_body(s3))
    assert r.status_code == 200, r.text
    assert r.json()["amount"] == 67.20
    row = db.db["orders"][0]
    assert row["order_status"] == "Awaiting Payment"
    assert row["phone"] == "9876543210"
    # Client cannot inject its own total or status
    r = client.post("/api/orders", json=order_body(s3, total_amount=1, order_status="Delivered"))
    assert r.json()["amount"] == 67.20


def test_quote_matches_frontend_examples(env):
    main, *_ = load_app(env)
    q = main.compute_quote(effective_pages=12, n_up=4, copies=1, color=True, duplex=True, binding="spiral", rates=main.DEFAULT_RATES)
    assert q["total"] == 111.30 and q["sheets"] == 2
    q = main.compute_quote(effective_pages=500, n_up=1, copies=1, color=False, duplex=False, binding="none", rates=main.DEFAULT_RATES)
    assert q["delivery_cost"] == 0  # free delivery above threshold


def test_order_rejects_bad_input(env):
    main, client, db, s3 = load_app(env)
    assert client.post("/api/orders", json=order_body(s3, phone="12345")).status_code == 422
    assert client.post("/api/orders", json=order_body(s3, pincode="12")).status_code == 422
    assert client.post("/api/orders", json=order_body(s3, page_range_mode="custom", page_range_spec="5-99")).status_code == 400
    bad_key = order_body(s3)
    bad_key["files"][0]["key"] = "../../etc/passwd"
    assert client.post("/api/orders", json=bad_key).status_code == 422
    missing = order_body(s3)
    missing["files"][0]["key"] = "orders/" + "b" * 32 + ".pdf"  # never uploaded
    assert client.post("/api/orders", json=missing).status_code == 400


def test_custom_range_counts_pages(env):
    main, client, db, s3 = load_app(env)
    r = client.post("/api/orders", json=order_body(s3, page_range_mode="custom", page_range_spec="1, 3-5"))
    assert r.status_code == 200
    assert db.db["orders"][0]["effective_pages"] == 4
    assert r.json()["amount"] == 50.40


def test_utr_flow_and_tracking_requires_phone(env):
    main, client, db, s3 = load_app(env)
    oid = client.post("/api/orders", json=order_body(s3)).json()["order_id"]

    # wrong phone cannot submit or track
    assert client.post(f"/api/orders/{oid}/utr", json={"phone": "9000000000", "utr": "123456789012"}).status_code == 404
    assert client.get("/api/track", params={"order_id": oid, "phone": "9000000000"}).status_code == 404
    assert client.post(f"/api/orders/{oid}/utr", json={"phone": "9876543210", "utr": "12345"}).status_code == 422

    r = client.post(f"/api/orders/{oid}/utr", json={"phone": "9876543210", "utr": "123456789012"})
    assert r.status_code == 200
    t = client.get("/api/track", params={"order_id": oid.lower(), "phone": "98765 43210"})
    assert t.status_code == 200 and t.json()["order_status"] == "Awaiting UTR Verification"
    assert "utr_number" not in t.json() and "phone" not in t.json()

    # same UTR cannot be reused on another order
    oid2 = client.post("/api/orders", json=order_body(s3)).json()["order_id"]
    assert client.post(f"/api/orders/{oid2}/utr", json={"phone": "9876543210", "utr": "123456789012"}).status_code == 409


def test_staff_pin_and_lockout(env):
    main, client, db, s3 = load_app(env)
    assert client.post("/api/staff/login", json={"pin": OWNER_PIN}).json()["role"] == "owner"
    assert client.post("/api/staff/login", json={"pin": WORKER_PIN}).json()["role"] == "worker"
    assert client.get("/api/admin/orders").status_code == 401
    assert client.get("/api/admin/orders", headers={"X-Staff-Pin": "0000"}).status_code == 401
    for _ in range(4):
        client.post("/api/staff/login", json={"pin": "nope"})
    r = client.post("/api/staff/login", json={"pin": OWNER_PIN})
    assert r.status_code == 429  # locked out even with the right PIN


def test_staff_workflow_verify_reject_download_purge(env):
    main, client, db, s3 = load_app(env)
    owner = {"X-Staff-Pin": OWNER_PIN}
    worker = {"X-Staff-Pin": WORKER_PIN}
    oid = client.post("/api/orders", json=order_body(s3)).json()["order_id"]
    key = db.db["orders"][0]["file_key"]

    # unpaid: cannot be moved to production or downloaded
    assert client.patch(f"/api/admin/orders/{oid}", json={"status": "Printing in Progress"}, headers=worker).status_code == 409
    assert client.get(f"/api/admin/download/{oid}", headers=worker).status_code == 409

    client.post(f"/api/orders/{oid}/utr", json={"phone": "9876543210", "utr": "111122223333"})
    # reject, customer sees reason, resubmits, staff accepts
    r = client.patch(f"/api/admin/orders/{oid}", json={"status": "Payment Rejected", "rejection_reason": "UTR not found"}, headers=worker)
    assert r.status_code == 200
    t = client.get("/api/track", params={"order_id": oid, "phone": "9876543210"}).json()
    assert t["order_status"] == "Payment Rejected" and t["rejection_reason"] == "UTR not found"
    client.post(f"/api/orders/{oid}/utr", json={"phone": "9876543210", "utr": "111122224444"})
    assert client.patch(f"/api/admin/orders/{oid}", json={"status": "Order Received"}, headers=worker).status_code == 200
    assert client.patch(f"/api/admin/orders/{oid}", json={"status": "Hacked"}, headers=worker).status_code == 400

    # worker does not see amounts; owner does
    assert client.get("/api/admin/orders", headers=worker).json()["orders"][0]["total_amount"] is None
    assert client.get("/api/admin/orders", headers=owner).json()["orders"][0]["total_amount"] == 67.20

    d = client.get(f"/api/admin/download/{oid}", headers=worker)
    assert d.status_code == 200 and d.content == b"%PDF-1.4 test"
    assert key not in s3.objects  # purged after download
    assert db.db["orders"][0]["file_status"] == "PURGED"
    assert client.get(f"/api/admin/download/{oid}", headers=worker).status_code == 410


def test_settings_owner_only_and_used_for_pricing(env):
    main, client, db, s3 = load_app(env)
    body = {"shop_name": "Copy Corner", "upi_id": "shop@okaxis", "rates": {**main.DEFAULT_RATES, "bw_page": 3.0}}
    assert client.put("/api/admin/settings", json=body, headers={"X-Staff-Pin": WORKER_PIN}).status_code == 403
    r = client.put("/api/admin/settings", json=body, headers={"X-Staff-Pin": OWNER_PIN})
    assert r.status_code == 200 and r.json()["shop_name"] == "Copy Corner"
    assert client.get("/api/settings").json()["rates"]["bw_page"] == 3.0
    # 12 x 3 + 40 = 76, +5% = 79.80
    assert client.post("/api/orders", json=order_body(s3)).json()["amount"] == 79.80
    bad = {**body, "upi_id": "not a upi"}
    assert client.put("/api/admin/settings", json=bad, headers={"X-Staff-Pin": OWNER_PIN}).status_code == 422


def test_razorpay_signature_verification(env, monkeypatch):
    main, client, db, s3 = load_app(env, razorpay=True)
    monkeypatch.setattr(main, "razorpay_request", lambda method, path, payload=None: {"id": "order_RZP1"})
    res = client.post("/api/orders", json=order_body(s3)).json()
    oid = res["order_id"]
    assert res["razorpay_order_id"] == "order_RZP1"

    forged = {"razorpay_payment_id": "pay_1", "razorpay_order_id": "order_RZP1", "razorpay_signature": "deadbeef"}
    assert client.post(f"/api/orders/{oid}/razorpay-verify", json=forged).status_code == 400
    assert db.db["orders"][0]["order_status"] == "Awaiting Payment"

    sig = hmac.new(RZP_SECRET.encode(), b"order_RZP1|pay_1", hashlib.sha256).hexdigest()
    ok = {**forged, "razorpay_signature": sig}
    assert client.post(f"/api/orders/{oid}/razorpay-verify", json=ok).status_code == 200
    assert db.db["orders"][0]["order_status"] == "Order Received"
    assert db.db["orders"][0]["utr_number"] == "RZP:pay_1"


def test_upload_url_restricts_file_types(env):
    main, client, db, s3 = load_app(env)
    assert client.get("/api/upload-url", params={"filename": "evil.exe"}).status_code == 400
    r = client.get("/api/upload-url", params={"filename": "Report.PDF"}).json()
    assert main.FILE_KEY_RE.fullmatch(r["file_key"]) and r["content_type"] == "application/pdf"
