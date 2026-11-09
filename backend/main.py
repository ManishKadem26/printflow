"""PrintFlow backend.

All database access goes through this server (using the Supabase service key), so the
browser never reads or writes the `orders` table directly. The server:
  * recomputes every price from the shop's rates (the browser's total is never trusted),
  * verifies Razorpay payments by signature,
  * checks staff PINs (with lockout) for every staff action,
  * hands out short-lived R2 upload URLs and streams + purges files for staff.
"""

import base64
import hashlib
import hmac
import io
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Literal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from supabase import create_client

load_dotenv()


def require_env(name: str) -> str:
    """Read a required setting from the environment / backend/.env; never fall back to a hardcoded secret."""
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}. Copy backend/.env.example to backend/.env and fill it in.")
    return value


R2_ENDPOINT_URL = require_env("R2_ENDPOINT_URL")
R2_ACCESS_KEY_ID = require_env("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = require_env("R2_SECRET_ACCESS_KEY")
BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "printflow-uploads")

SUPABASE_URL = require_env("SUPABASE_URL")
SUPABASE_SERVICE_KEY = require_env("SUPABASE_SERVICE_KEY")

WORKER_PIN = require_env("WORKER_SECRET_PIN")
OWNER_PIN = require_env("OWNER_SECRET_PIN")
if len(WORKER_PIN) < 4 or len(OWNER_PIN) < 4 or WORKER_PIN == OWNER_PIN:
    raise RuntimeError("WORKER_SECRET_PIN and OWNER_SECRET_PIN must be at least 4 characters and different from each other.")

# Optional: Razorpay. Without these, customers pay by direct UPI + UTR only.
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
RAZORPAY_ENABLED = bool(RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET)

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]

s3_client = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT_URL,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    config=Config(signature_version="s3v4"),
    region_name="auto",
)
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

app = FastAPI(title="PrintFlow Backend API", version="6.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Content-Type", "X-Staff-Pin"],
    expose_headers=["Content-Disposition"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STATUS_AWAITING_PAYMENT = "Awaiting Payment"
STATUS_AWAITING_UTR = "Awaiting UTR Verification"
STATUS_REJECTED = "Payment Rejected"
PRODUCTION_STAGES = ["Order Received", "Printing in Progress", "Binding & QC", "Out for Delivery", "Delivered"]

UPLOAD_TYPES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
}
FILE_KEY_RE = re.compile(r"^orders/[0-9a-f]{32}\.(pdf|docx?|jpe?g|png)$")

DEFAULT_RATES = {
    "bw_page": 2.0,
    "bw_duplex": 1.5,
    "color_page": 8.0,
    "color_duplex": 7.0,
    "staple": 5.0,
    "spiral": 45.0,
    "wiro": 75.0,
    "hard": 220.0,
    "delivery_fee": 40.0,
    "free_delivery_threshold": 499.0,
}
DEFAULT_SETTINGS = {"shop_name": "PrintFlow", "upi_id": "", "rates": DEFAULT_RATES}
GST_RATE = 0.05


# ---------------------------------------------------------------------------
# Rate limiting & staff auth
# ---------------------------------------------------------------------------
class RateLimiter:
    """Small in-memory sliding-window limiter keyed by client IP (fine for a single server process)."""

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self.lock:
            recent = [t for t in self.hits.get(key, []) if now - t < self.window]
            if len(recent) >= self.limit:
                self.hits[key] = recent
                raise HTTPException(status_code=429, detail="Too many requests. Please wait a moment and try again.")
            recent.append(now)
            self.hits[key] = recent


track_limiter = RateLimiter(limit=20, window_seconds=60)
order_limiter = RateLimiter(limit=10, window_seconds=60)
upload_limiter = RateLimiter(limit=30, window_seconds=60)

PIN_MAX_FAILURES = 5
PIN_LOCKOUT_SECONDS = 300
_pin_failures: dict[str, list[float]] = {}
_pin_lock = threading.Lock()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def resolve_role(pin: str | None, ip: str) -> str:
    """Return 'owner' or 'worker' for a valid PIN; count failures and lock out brute-force attempts."""
    now = time.monotonic()
    with _pin_lock:
        failures = [t for t in _pin_failures.get(ip, []) if now - t < PIN_LOCKOUT_SECONDS]
        _pin_failures[ip] = failures
        if len(failures) >= PIN_MAX_FAILURES:
            retry = int(PIN_LOCKOUT_SECONDS - (now - failures[0])) + 1
            raise HTTPException(status_code=429, detail=f"Too many wrong PINs. Locked for {retry}s.", headers={"Retry-After": str(retry)})

    candidate = (pin or "").encode()
    if hmac.compare_digest(candidate, OWNER_PIN.encode()):
        role = "owner"
    elif hmac.compare_digest(candidate, WORKER_PIN.encode()):
        role = "worker"
    else:
        with _pin_lock:
            _pin_failures.setdefault(ip, []).append(now)
            left = PIN_MAX_FAILURES - len(_pin_failures[ip])
        raise HTTPException(status_code=401, detail=f"Invalid PIN. {max(left, 0)} attempts left.")

    with _pin_lock:
        _pin_failures.pop(ip, None)
    return role


def staff_role(request: Request, x_staff_pin: str | None = Header(None)) -> str:
    return resolve_role(x_staff_pin, client_ip(request))


def owner_role(role: str = Depends(staff_role)) -> str:
    if role != "owner":
        raise HTTPException(status_code=403, detail="Only the shop owner can do this.")
    return role


# ---------------------------------------------------------------------------
# Settings & pricing
# ---------------------------------------------------------------------------
def load_settings() -> dict:
    try:
        res = supabase.table("shop_settings").select("shop_name, upi_id, rates").eq("id", 1).limit(1).execute()
        row = res.data[0] if res.data else {}
    except Exception:
        row = {}
    rates = {**DEFAULT_RATES, **{k: float(v) for k, v in (row.get("rates") or {}).items() if k in DEFAULT_RATES}}
    return {
        "shop_name": row.get("shop_name") or DEFAULT_SETTINGS["shop_name"],
        "upi_id": row.get("upi_id") or DEFAULT_SETTINGS["upi_id"],
        "rates": rates,
    }


def parse_page_range(spec: str, total_pages: int) -> list[int]:
    pages: set[int] = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(\d+)\s*(?:-\s*(\d+))?", part)
        if not m:
            raise ValueError(f'"{part}" is not a valid page or range')
        start = int(m.group(1))
        end = int(m.group(2) or start)
        if start < 1 or end < start:
            raise ValueError(f'"{part}" is not a valid range')
        if end > total_pages:
            raise ValueError(f"Page {end} exceeds the {total_pages} pages in your documents")
        pages.update(range(start, end + 1))
    if not pages:
        raise ValueError("Page range is empty")
    return sorted(pages)


def compute_quote(*, effective_pages: int, n_up: int, copies: int, color: bool, duplex: bool, binding: str, rates: dict) -> dict:
    """Same formula the order form shows. Returns amounts rounded to paise."""
    sides_per_copy = math.ceil(effective_pages / n_up)
    sheets_per_copy = math.ceil(sides_per_copy / 2) if duplex else sides_per_copy
    per_side = (rates["color_duplex"] if duplex else rates["color_page"]) if color else (rates["bw_duplex"] if duplex else rates["bw_page"])
    print_cost = sides_per_copy * copies * per_side
    binding_cost = (0.0 if binding == "none" else rates[binding]) * copies
    items = print_cost + binding_cost
    delivery = 0.0 if items >= rates["free_delivery_threshold"] else rates["delivery_fee"]
    subtotal = items + delivery
    gst = round(subtotal * GST_RATE, 2)
    return {
        "print_cost": round(print_cost, 2),
        "binding_cost": round(binding_cost, 2),
        "delivery_cost": round(delivery, 2),
        "gst": gst,
        "total": round(subtotal + gst, 2),
        "sheets": sheets_per_copy * copies,
    }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class OrderFile(BaseModel):
    key: str
    name: str = Field(min_length=1, max_length=200)
    pages: int = Field(ge=1, le=5000)
    size_mb: float = Field(ge=0, le=500)

    @field_validator("key")
    @classmethod
    def key_must_come_from_upload_url(cls, v: str) -> str:
        if not FILE_KEY_RE.fullmatch(v):
            raise ValueError("invalid file key")
        return v


class OrderCreate(BaseModel):
    customer_name: str = Field(min_length=1, max_length=80)
    phone: str
    address: str = Field(min_length=3, max_length=300)
    landmark: str = Field(default="", max_length=150)
    city: str = Field(default="", max_length=80)
    pincode: str
    instructions: str = Field(default="", max_length=500)
    files: list[OrderFile] = Field(min_length=1, max_length=20)
    page_range_mode: Literal["all", "custom"] = "all"
    page_range_spec: str = Field(default="", max_length=200)
    orientation: Literal["portrait", "landscape"] = "portrait"
    n_up_layout: Literal[1, 2, 4, 6, 9, 16] = 1
    copies: int = Field(default=1, ge=1, le=999)
    color_mode: Literal["bw", "color"]
    sides: Literal["single", "double"]
    paper_size: Literal["A4", "A3", "Legal", "Photo"] = "A4"
    paper_gsm: Literal["75", "100", "300"] = "75"
    binding: Literal["none", "staple", "spiral", "wiro", "hard"] = "none"

    @field_validator("phone")
    @classmethod
    def indian_mobile(cls, v: str) -> str:
        digits = re.sub(r"\D", "", v)[-10:]
        if not re.fullmatch(r"[6-9]\d{9}", digits):
            raise ValueError("enter a valid 10-digit mobile number")
        return digits

    @field_validator("pincode")
    @classmethod
    def six_digit_pin(cls, v: str) -> str:
        digits = re.sub(r"\D", "", v)
        if not re.fullmatch(r"\d{6}", digits):
            raise ValueError("enter a valid 6-digit pincode")
        return digits

    @field_validator("customer_name", "address", "landmark", "city", "instructions")
    @classmethod
    def strip_text(cls, v: str) -> str:
        return v.strip()


class UtrSubmit(BaseModel):
    phone: str
    utr: str

    @field_validator("utr")
    @classmethod
    def twelve_digits(cls, v: str) -> str:
        if not re.fullmatch(r"\d{12}", v.strip()):
            raise ValueError("UTR must be exactly 12 digits")
        return v.strip()


class RazorpayVerify(BaseModel):
    razorpay_payment_id: str = Field(min_length=1, max_length=64)
    razorpay_order_id: str = Field(min_length=1, max_length=64)
    razorpay_signature: str = Field(min_length=1, max_length=128)


class StaffLogin(BaseModel):
    pin: str = Field(max_length=32)


class OrderUpdate(BaseModel):
    status: str | None = None
    rejection_reason: str | None = Field(default=None, max_length=300)


class RatesUpdate(BaseModel):
    bw_page: float = Field(gt=0, le=1000)
    bw_duplex: float = Field(gt=0, le=1000)
    color_page: float = Field(gt=0, le=1000)
    color_duplex: float = Field(gt=0, le=1000)
    staple: float = Field(ge=0, le=10000)
    spiral: float = Field(ge=0, le=10000)
    wiro: float = Field(ge=0, le=10000)
    hard: float = Field(ge=0, le=10000)
    delivery_fee: float = Field(ge=0, le=10000)
    free_delivery_threshold: float = Field(ge=0, le=1000000)


class SettingsUpdate(BaseModel):
    shop_name: str = Field(min_length=1, max_length=60)
    upi_id: str = Field(max_length=100)
    rates: RatesUpdate

    @field_validator("upi_id")
    @classmethod
    def upi_format(cls, v: str) -> str:
        v = v.strip()
        if v and not re.fullmatch(r"[\w.\-]{2,256}@[a-zA-Z]{2,64}", v):
            raise ValueError("invalid UPI ID")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_order(order_id: str, columns: str = "*") -> dict:
    res = supabase.table("orders").select(columns).eq("id", order_id).limit(1).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Order not found")
    return res.data[0]


def order_files(order: dict) -> list[dict]:
    files = order.get("files") or []
    if not files and order.get("file_key"):
        files = [{"key": order["file_key"], "name": order.get("file_name") or "document"}]
    return files


def razorpay_request(method: str, path: str, payload: dict | None = None) -> dict:
    token = base64.b64encode(f"{RAZORPAY_KEY_ID}:{RAZORPAY_KEY_SECRET}".encode()).decode()
    req = urllib.request.Request(
        f"https://api.razorpay.com/v1{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Razorpay error ({e.code})") from e
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail="Could not reach Razorpay") from e


def utr_already_used(utr: str, exclude_order_id: str) -> bool:
    res = supabase.table("orders").select("id").eq("utr_number", utr).neq("id", exclude_order_id).limit(1).execute()
    return bool(res.data)


def public_order_view(o: dict) -> dict:
    """What a customer may see when tracking (they proved ownership with order ID + phone)."""
    keys = ["id", "order_status", "created_at", "file_name", "effective_pages", "copies", "n_up_layout",
            "color_mode", "sides", "paper_size", "binding", "address", "pincode", "total_amount",
            "rejection_reason", "file_status"]
    return {k: o.get(k) for k in keys}


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
def check_health():
    try:
        s3_client.head_bucket(Bucket=BUCKET_NAME)
    except Exception as e:
        raise HTTPException(status_code=503, detail="Storage unavailable") from e
    return {"status": "ok"}


@app.get("/api/settings")
def get_public_settings():
    s = load_settings()
    return {**s, "razorpay_enabled": RAZORPAY_ENABLED, "razorpay_key_id": RAZORPAY_KEY_ID if RAZORPAY_ENABLED else None}


@app.get("/api/upload-url")
def generate_r2_upload_url(request: Request, filename: str, content_type: str = "application/pdf"):
    upload_limiter.check(client_ip(request))
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in UPLOAD_TYPES:
        raise HTTPException(status_code=400, detail="Only PDF, Word, JPG and PNG files are accepted.")
    content_type = UPLOAD_TYPES[ext]
    file_key = f"orders/{uuid.uuid4().hex}.{ext}"
    upload_url = s3_client.generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": BUCKET_NAME, "Key": file_key, "ContentType": content_type},
        ExpiresIn=600,
    )
    return {"upload_url": upload_url, "file_key": file_key, "content_type": content_type}


@app.post("/api/orders")
def create_order(order: OrderCreate, request: Request):
    """Create an order in 'Awaiting Payment' with a server-computed price."""
    order_limiter.check(client_ip(request))

    for f in order.files:
        try:
            s3_client.head_object(Bucket=BUCKET_NAME, Key=f.key)
        except ClientError:
            raise HTTPException(status_code=400, detail=f"File {f.name} was not uploaded. Please upload it again.")

    total_doc_pages = sum(f.pages for f in order.files)
    if order.page_range_mode == "custom":
        try:
            effective_pages = len(parse_page_range(order.page_range_spec, total_doc_pages))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        page_range_spec = re.sub(r"\s+", "", order.page_range_spec)
    else:
        effective_pages = total_doc_pages
        page_range_spec = f"1-{total_doc_pages}"

    settings = load_settings()
    quote = compute_quote(
        effective_pages=effective_pages, n_up=order.n_up_layout, copies=order.copies,
        color=order.color_mode == "color", duplex=order.sides == "double",
        binding=order.binding, rates=settings["rates"],
    )

    first = order.files[0]
    file_name = first.name if len(order.files) == 1 else f"{first.name} (+{len(order.files) - 1} more)"
    row = {
        "customer_name": order.customer_name,
        "phone": order.phone,
        "file_name": file_name,
        "file_key": first.key,
        "files": [f.model_dump() for f in order.files],
        "file_size_mb": round(sum(f.size_mb for f in order.files), 2),
        "file_status": "IN CLOUD",
        "total_doc_pages": total_doc_pages,
        "page_range_mode": order.page_range_mode,
        "page_range_spec": page_range_spec,
        "effective_pages": effective_pages,
        "orientation": order.orientation,
        "n_up_layout": order.n_up_layout,
        "copies": order.copies,
        "color_mode": "Colour" if order.color_mode == "color" else "B&W",
        "sides": "Back-to-Back" if order.sides == "double" else "Single Sided",
        "paper_size": order.paper_size,
        "paper_gsm": order.paper_gsm,
        "binding": order.binding.upper(),
        "address": ", ".join(p for p in [order.address, order.city] if p),
        "landmark": order.landmark,
        "pincode": order.pincode,
        "instructions": order.instructions,
        "total_amount": quote["total"],
        "utr_number": "",
        "order_status": STATUS_AWAITING_PAYMENT,
    }

    for _ in range(3):
        row["id"] = f"PF-{uuid.uuid4().hex[:6].upper()}"
        try:
            supabase.table("orders").insert(row).execute()
            break
        except Exception as e:
            if "duplicate" not in str(e).lower():
                raise HTTPException(status_code=500, detail="Could not save the order. Please try again.") from e
    else:
        raise HTTPException(status_code=500, detail="Could not allocate an order ID. Please try again.")

    response = {"order_id": row["id"], "amount": quote["total"], "quote": quote, "razorpay_order_id": None}
    if RAZORPAY_ENABLED:
        try:
            rzp = razorpay_request("POST", "/orders", {"amount": int(round(quote["total"] * 100)), "currency": "INR", "receipt": row["id"]})
            supabase.table("orders").update({"razorpay_order_id": rzp["id"]}).eq("id", row["id"]).execute()
            response["razorpay_order_id"] = rzp["id"]
            response["razorpay_key_id"] = RAZORPAY_KEY_ID
        except HTTPException:
            pass  # customer can still pay by direct UPI
    return response


@app.post("/api/orders/{order_id}/razorpay-verify")
def verify_razorpay_payment(order_id: str, body: RazorpayVerify):
    if not RAZORPAY_ENABLED:
        raise HTTPException(status_code=400, detail="Razorpay is not enabled")
    order = get_order(order_id, "id, order_status, razorpay_order_id, total_amount")
    if order.get("razorpay_order_id") != body.razorpay_order_id:
        raise HTTPException(status_code=400, detail="Payment does not belong to this order")
    expected = hmac.new(RAZORPAY_KEY_SECRET.encode(), f"{body.razorpay_order_id}|{body.razorpay_payment_id}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, body.razorpay_signature):
        raise HTTPException(status_code=400, detail="Payment signature is invalid")
    if order["order_status"] == STATUS_AWAITING_PAYMENT:
        supabase.table("orders").update({
            "order_status": PRODUCTION_STAGES[0],
            "utr_number": f"RZP:{body.razorpay_payment_id}",
            "paid_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", order_id).execute()
    return {"status": "paid", "order_id": order_id, "amount": order["total_amount"]}


@app.post("/api/orders/{order_id}/utr")
def submit_utr(order_id: str, body: UtrSubmit, request: Request):
    """Customer submits (or, after a rejection, resubmits) the UPI reference for a direct UPI payment."""
    order_limiter.check(client_ip(request))
    order = get_order(order_id, "id, phone, order_status")
    if not hmac.compare_digest(re.sub(r"\D", "", body.phone)[-10:], order["phone"]):
        raise HTTPException(status_code=404, detail="Order not found")
    if order["order_status"] not in (STATUS_AWAITING_PAYMENT, STATUS_REJECTED, STATUS_AWAITING_UTR):
        raise HTTPException(status_code=409, detail="This order is already paid.")
    if utr_already_used(body.utr, order_id):
        raise HTTPException(status_code=409, detail="This UTR has already been used for another order.")
    supabase.table("orders").update({
        "utr_number": body.utr,
        "order_status": STATUS_AWAITING_UTR,
        "rejection_reason": None,
    }).eq("id", order_id).execute()
    return {"status": STATUS_AWAITING_UTR, "order_id": order_id}


@app.get("/api/track")
def track_order(order_id: str, phone: str, request: Request):
    track_limiter.check(client_ip(request))
    digits = re.sub(r"\D", "", phone)[-10:]
    res = supabase.table("orders").select("*").eq("id", order_id.strip().upper()).limit(1).execute()
    if not res.data or not hmac.compare_digest(res.data[0].get("phone") or "", digits):
        raise HTTPException(status_code=404, detail="No order matches that Order ID and phone number.")
    return public_order_view(res.data[0])


# ---------------------------------------------------------------------------
# Staff endpoints (X-Staff-Pin header)
# ---------------------------------------------------------------------------
@app.post("/api/staff/login")
def staff_login(body: StaffLogin, request: Request):
    return {"role": resolve_role(body.pin, client_ip(request))}


@app.get("/api/admin/orders")
def list_orders(role: str = Depends(staff_role), limit: int = 200):
    res = supabase.table("orders").select("*").order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute()
    rows = res.data or []
    if role != "owner":
        for r in rows:
            r["total_amount"] = None  # revenue is owner-only
    return {"orders": rows, "role": role}


@app.patch("/api/admin/orders/{order_id}")
def update_order(order_id: str, body: OrderUpdate, role: str = Depends(staff_role)):
    order = get_order(order_id, "id, order_status")
    if body.rejection_reason is not None or body.status == STATUS_REJECTED:
        if order["order_status"] not in (STATUS_AWAITING_UTR, STATUS_AWAITING_PAYMENT):
            raise HTTPException(status_code=409, detail="Only unverified payments can be rejected.")
        update = {"order_status": STATUS_REJECTED,
                  "rejection_reason": (body.rejection_reason or "Payment could not be verified.").strip()}
    elif body.status in PRODUCTION_STAGES:
        if order["order_status"] == STATUS_AWAITING_PAYMENT:
            raise HTTPException(status_code=409, detail="The customer has not paid for this order yet.")
        update = {"order_status": body.status}
        if order["order_status"] in (STATUS_AWAITING_UTR, STATUS_REJECTED):
            update["paid_at"] = datetime.now(timezone.utc).isoformat()
            update["rejection_reason"] = None
    else:
        raise HTTPException(status_code=400, detail="Unknown status")
    supabase.table("orders").update(update).eq("id", order_id).execute()
    return {"id": order_id, **update}


@app.put("/api/admin/settings")
def update_settings(body: SettingsUpdate, role: str = Depends(owner_role)):
    row = {"id": 1, "shop_name": body.shop_name.strip(), "upi_id": body.upi_id, "rates": body.rates.model_dump(),
           "updated_at": datetime.now(timezone.utc).isoformat()}
    supabase.table("shop_settings").upsert(row).execute()
    return get_public_settings()


def purge_files(keys: list[str], order_id: str):
    for key in keys:
        try:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=key)
        except Exception:
            pass
    supabase.table("orders").update({"file_status": "PURGED", "file_size_mb": 0}).eq("id", order_id).execute()


@app.get("/api/admin/download/{order_id}")
def download_and_auto_purge(order_id: str, background_tasks: BackgroundTasks, role: str = Depends(staff_role)):
    order = get_order(order_id)
    if order.get("order_status") in (STATUS_AWAITING_PAYMENT, STATUS_AWAITING_UTR, STATUS_REJECTED):
        raise HTTPException(status_code=409, detail="Verify the payment before downloading this order.")
    if order.get("file_status") == "PURGED":
        raise HTTPException(status_code=410, detail="This file was already downloaded and purged.")
    files = order_files(order)
    if not files:
        raise HTTPException(status_code=404, detail="This order has no files.")

    safe = lambda name: re.sub(r'[^\w.\- ()]', "_", name)[:150] or "document"
    try:
        if len(files) == 1:
            obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=files[0]["key"])
            body, filename = obj["Body"], f"{order_id}_{safe(files[0]['name'])}"
        else:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for i, f in enumerate(files, 1):
                    data = s3_client.get_object(Bucket=BUCKET_NAME, Key=f["key"])["Body"].read()
                    zf.writestr(f"{i:02d}_{safe(f['name'])}", data)
            buf.seek(0)
            body, filename = buf, f"{order_id}_files.zip"
    except ClientError as e:
        raise HTTPException(status_code=404, detail="File is missing from storage.") from e

    background_tasks.add_task(purge_files, [f["key"] for f in files], order_id)
    return StreamingResponse(body, media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------------
# Website: serve frontend/ from the same address as the API (one service to host).
# Mounted last so every /api/... route above takes priority.
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.getenv("FRONTEND_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
