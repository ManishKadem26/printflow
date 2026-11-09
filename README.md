# PrintFlow — Print & Doorstep Delivery

## Structure
- `frontend/index.html`: customer order page, order tracking, and the PIN-protected staff console
- `backend/main.py`: FastAPI server — the only thing that talks to the database and file storage
- `backend/.env.example`: template for `backend/.env` (your real keys; never commit or share it)
- `backend/tests/`: backend tests (in-memory fakes, no real data touched)
- `database/schema.sql`: fresh database setup
- `database/migrations/002_secure_backend_only.sql`: upgrade for an existing database

## How it is secured
- The browser never reads or writes the database. Database rules give the public key **no** access.
- Prices are recalculated on the server from the shop's rates; the browser's total is never trusted.
- Razorpay payments are confirmed by signature on the server. Direct UPI orders wait for staff to check the UTR, and a UTR can't be reused.
- Staff PINs live only in `backend/.env`; wrong PINs lock out for 5 minutes after 5 tries.
- Customers track an order with **Order ID + mobile number**.
- Files can only be downloaded after payment is verified, and are deleted from storage once downloaded.

## Setup
1. **Database:** in the Supabase SQL editor, run `database/migrations/002_secure_backend_only.sql`
   (or `database/schema.sql` for a new project).
2. **Backend:**
   ```bash
   cd backend
   cp .env.example .env   # then fill in your keys and PINs
   pip install -r requirements.txt
   uvicorn main:app --port 8000
   ```
3. **Frontend:** serve `frontend/` with any static web server. If the backend isn't at
   `http://localhost:8000`, add `<script>window.PRINTFLOW_API_URL = "https://your-api";</script>`
   before the app script, or set it in the staff console (owner → Backend server URL).
4. In production set `ALLOWED_ORIGINS` in `.env` to your site's address.

## Tests
```bash
cd backend
pip install pytest httpx
python -m pytest tests -q
```
