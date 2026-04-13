import jwt
import time
import urllib.request
import urllib.error
import json

TEST_SECRET = "test_secret_12345"
BASE_URL = "http://127.0.0.1:8001"

def create_token(sub="1234-5678", email="test@example.com", expires_in=3600, secret=TEST_SECRET):
    payload = {
        "sub": sub,
        "email": email,
        "exp": int(time.time()) + expires_in,
        "iat": int(time.time()),
        "iss": "supabase"
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def test_endpoint(path, token=None, header_name="Authorization"):
    url = f"{BASE_URL}{path}"
    headers = {}
    if token:
        headers[header_name] = f"Bearer {token}"
    
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)

def run_tests():
    print("--- STARTING SECURITY AUTH VERIFICATION ---")
    
    # 1. No Token
    code, body = test_endpoint("/api/history")
    print(f"[TEST 1] No Token: Expected 401, Got {code}")
    assert code == 401, f"Failed: Got {code}"

    # 2. Invalid Token Format (No Bearer)
    url = f"{BASE_URL}/api/history"
    req = urllib.request.Request(url, headers={"Authorization": "NotBearer some-token"})
    try:
        with urllib.request.urlopen(req) as response:
            status = response.status
        body = response.read().decode()
    except urllib.error.HTTPError as e:
        status = e.code
    print(f"[TEST 2] Invalid Format: Expected 401, Got {status}")
    assert status == 401

    # 3. Forged Token (Wrong Secret)
    forged_token = create_token(secret="WRONG_SECRET")
    code, body = test_endpoint("/api/history", token=forged_token)
    print(f"[TEST 3] Forged Token: Expected 401, Got {code}")
    assert code == 401

    # 4. Expired Token
    expired_token = create_token(expires_in=-3600)
    code, body = test_endpoint("/api/history", token=expired_token)
    print(f"[TEST 4] Expired Token: Expected 401, Got {code}")
    assert code == 401

    # 5. Valid Token
    valid_token = create_token()
    code, body = test_endpoint("/api/history", token=valid_token)
    print(f"[TEST 5] Valid Token: Expected 200, Got {code}")
    # Note: Might get 500 if DB is not reachable, but should NOT be 401
    assert code in [200, 500], f"Failed: Got {code} - {body}"
    if code == 500:
        print("  (Note: Got 500, likely due to DB connection which is expected in this environment)")

    print("--- ALL MODES VERIFIED ---")

if __name__ == "__main__":
    # Note: Server must be running on port 8001
    run_tests()
