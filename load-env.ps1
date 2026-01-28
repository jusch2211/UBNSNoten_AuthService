Get-Content .env | ForEach-Object {
  if ($_ -match "^\s*([^#=]+)=(.*)$") {
    Set-Item -Path Env:$($matches[1]) -Value $matches[2]
  }
}
