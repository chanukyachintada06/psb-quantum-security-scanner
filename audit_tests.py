import sys
import json
import urllib.request
from urllib.error import HTTPError

API_BASE = "http://localhost:8000/api"

# We will need the Supabase anon key and URL from the frontend to simulate login
SUPABASE_URL = "https://uiulgfwvswdoguzksaya.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVpdWxnZnd2c3dkb2d1emtzYXlhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU0Nzk1NjEsImV4cCI6MjA5MTA1NTU2MX0.PsyN6X0lbyP4q8Q6blaRM97B83idgItVQ5zxhEJ6yVA"
USER_EMAIL = "test@pnbhackathon.in"  # from the UI
USER_PASS = "admin123" # guessing from common prototypes, we might need to check if there is a known password, we'll see if it works

def request(method, path, data=None, token=None):
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    req_data = None
    if data:
         req_data = json.dumps(data).encode("utf-8")
         
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8")
        return e.code, body

print("--- RUNNING API SECURITY AUDIT ---")
print("1. Unauthorized Access Test:")
status, body = request("GET", "/assets")
print(f"GET /api/assets (No Auth) -> {status}: {str(body)[:500]}")

print("\n3. Fetching Assets (Authorized/Demo Mode):")
status, body = request("GET", "/assets")
print(f"GET /api/assets -> {status}: got {len(body.get('assets',[])) if isinstance(body, dict) else body} assets")

print("\n4. Running a valid scan (google.com):")
status, body = request("GET", "/scan/google.com")
print(f"GET /api/scan/google.com -> {status}")
if status == 200:
   pqc_data = body.get("pqc", {})
   print(f"  PQC Score: {pqc_data.get('risk_score')}")
   print(f"  Risk Level: {pqc_data.get('risk_level')}")
   # check for the new fields from the previous conversations
   rp = body.get("risk_profile", {})
   print(f"  Crypto Mode:     {rp.get('crypto_mode')}")
   print(f"  Quantum Risk Horizon: {rp.get('quantum_risk_horizon')}")
   print(f"  Crypto Agility Score: {rp.get('crypto_agility_score')}")
   print(f"  HNDL Risk: {rp.get('hndl_risk')}")
   
print("\n5. Running an invalid scan (invalid--domain-that-fails.xyzz):")
status, body = request("GET", "/scan/invalid--domain-that-fails.xyzz")
print(f"GET /api/scan/invalid... -> {status}")

print("\n6. Testing Trends API:")
status, body = request("GET", "/asset-trends/google.com")
scan_id = None
if status == 200 and isinstance(body, dict) and body.get("trends"):
    # The actual key might be id if they just returned the raw Supabase rows
    scan_id = body["trends"][0].get("id") or body["trends"][0].get("scan_id")
print(f"GET /api/asset-trends/google.com -> {status}, scan_id={scan_id}")

print("\n7. Testing Reports API:")
if scan_id:
    try:
       rep_req = urllib.request.Request(f"{API_BASE}/report/pdf/{scan_id}")
       with urllib.request.urlopen(rep_req) as res:
           print(f"GET /api/report/pdf/{scan_id} -> {res.status}, Type: {res.headers.get('Content-Type')}, Size: {len(res.read())} bytes")
    except HTTPError as e:
       print(f"PDF Export failed: {e.code} {e.read().decode()}")
else:
    print("Skipping Reports API test: no scan_id found.")

print("\n8. Testing Comparison API:")
status, body = request("GET", "/compare-assets-by-domain?domains=google.com,invalid.domain")
print(f"GET /compare-assets-by-domain -> {status}, body count: {len(body.get('comparisons', [])) if isinstance(body, dict) else str(body)[:50]}")

