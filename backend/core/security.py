"""Role-based API guard. Set PHISHGUARD_API_KEYS to a JSON map of token -> role in production."""
import hmac, json, os
from fastapi import Header, HTTPException, Depends

ROLE_LEVEL={"viewer":1,"analyst":2,"admin":3}
def get_role(x_api_key: str|None=Header(default=None)) -> str:
    raw=os.getenv("PHISHGUARD_API_KEYS", "").strip()
    if not raw: return "admin"  # local single-user mode; production should configure keys
    try: keys=json.loads(raw)
    except json.JSONDecodeError: raise HTTPException(500,"PHISHGUARD_API_KEYS must be valid JSON.")
    for token,role in keys.items():
        if x_api_key and hmac.compare_digest(str(token),x_api_key): return str(role).lower()
    raise HTTPException(401,"Valid X-API-Key required.")
def require_role(minimum="viewer"):
    def dependency(role: str=Depends(get_role)):
        if ROLE_LEVEL.get(role,0)<ROLE_LEVEL[minimum]: raise HTTPException(403,"Insufficient role permissions.")
        return role
    return dependency
