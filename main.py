from fastapi import FastAPI, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from config import ROUTES
from auth import authenticate, create_jwt, verify_jwt
from proxy import forward_request

app = FastAPI(title="Python API Gateway")
security = HTTPBearer()


@app.post("/auth/login")
def login(data: dict):
    user = authenticate(data["username"], data["password"])
    token = create_jwt(data["username"], user["roles"])
    return {"access_token": token}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(
    full_path: str,
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(security),
):
    token = creds.credentials
    claims = verify_jwt(token)

    path = f"/{full_path.split('/')[0]}"

    if path not in ROUTES:
        return {"error": "Route not found"}

    route = ROUTES[path]

    if not any(role in route["roles"] for role in claims["roles"]):
        return {"error": "Forbidden"}

    return await forward_request(
        request=request,
        target_url=route["target"],
        user=claims["sub"],
        roles=claims["roles"]
    )
