echo "[+] version check"
go build
./dalfox version 2>&1 | grep v

echo "[+] go test check"
go test ./...

echo "[+] goreleaser check"
goreleaser check
