JWT_SECRET = "change-this-secret"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 3600

ROUTES = {
    "/user": {
        "target": "http://localhost:8081",
        "roles": ["USER", "ADMIN"]
    },
    "/admin": {
        "target": "http://localhost:8082",
        "roles": ["ADMIN"]
    }
}
