$body = @{
    username = "admin"
    password = "..."
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri http://localhost:8080/auth/login `
    -Method POST `
    -Headers @{ "Content-Type" = "application/json" } `
    -Body $body

$response.Content
