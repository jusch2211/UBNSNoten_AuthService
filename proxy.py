import httpx
from fastapi import Request, Response

async def forward_request(
    request: Request,
    target_url: str,
    user: str,
    roles: list[str]
):
    async with httpx.AsyncClient() as client:

        url = f"{target_url}{request.url.path}"

        headers = dict(request.headers)
        headers["X-User"] = user
        headers["X-Roles"] = ",".join(roles)

        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=await request.body(),
            params=request.query_params
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response.headers
        )
