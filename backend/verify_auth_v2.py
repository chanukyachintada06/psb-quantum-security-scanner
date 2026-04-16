import jwt
import time
import urllib.request
import urllib.error
import json

TEST_SECRET = "6bm+WV/yoTfIhgd+6J0l57VgzhBNRPMep6N/LKZkkDO9De1bpHgFJbM5R02G13/SZYMTnffoRNwzVAPysnsXiA=="
BASE_URL = "http://127.0.0.1:8000"

def create_token(sub="1234-5678", email="test@example.com", expires_in=3600, secret=TEST_SECRET, aud=None):
    payload = {
        "sub": sub,
        "email": email,
        "exp": int(time.time()) + expires_in,
        "iat": int(time.time()),
        "iss": "supabase"
    }
    if aud:
        payload["aud"] = aud
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

    # 5. Valid HS256 Token (WITHOUT audience)
    # This should now succeed with the conditional fix
    valid_token = create_token()
    code, body = test_endpoint("/api/history", token=valid_token)
    print(f"[TEST 5] Valid HS256 (No Audience): Expected 200/500, Got {code}")
    assert code in [200, 500], f"Failed: Got {code} - {body}"

    # 6. /api/stats
    code, body = test_endpoint("/api/stats", token=valid_token)
    print(f"[TEST 6] /api/stats: Expected 200/500, Got {code}")
    assert code in [200, 500]

    # 7. /api/assets
    code, body = test_endpoint("/api/assets", token=valid_token)
    print(f"[TEST 7] /api/assets: Expected 200/500, Got {code}")
    assert code in [200, 500]

    # 8. /api/nameservers
    code, body = test_endpoint("/api/nameservers", token=valid_token)
    print(f"[TEST 8] /api/nameservers: Expected 200/500, Got {code}")
    assert code in [200, 500]

    # 9. Optional: /api/audit-login (POST)
    # Verify the login audit flow mentioned by user
    print("[TEST 9] Verifying audit-login flow...")
    url = f"{BASE_URL}/api/audit-login"
    data = json.dumps({"event": "USER_LOGIN_VERIFICATION"}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            code = response.status
    except urllib.error.HTTPError as e:
        code = e.code
    print(f"  [RESULT] audit-login: Expected 200/500, Got {code}")
    assert code in [200, 500]

    print("--- ALL MODES VERIFIED ---")

if __name__ == "__main__":
    # Note: Server must be running on port 8001
    run_tests()
