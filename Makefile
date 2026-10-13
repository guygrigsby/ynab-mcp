.PHONY: test race vet fmt-check build check fuzz vuln

test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
fmt-check:
	@test -z "$$(gofmt -l $$(git ls-files '*.go'; git ls-files --others --exclude-standard '*.go'))"
build:
	go build ./...
check: fmt-check vet test race build
fuzz:
	go test ./internal/adapters/mcp -run '^$$' -fuzz FuzzArguments -fuzztime 10s
	go test ./internal/application/credentials -run '^$$' -fuzz FuzzProtectedBundleDecode -fuzztime 10s
	go test ./internal/adapters/ynaboauth -run '^$$' -fuzz FuzzTokenResponseValidation -fuzztime 5s
	go test ./internal/adapters/auth -run '^$$' -fuzz FuzzVerifierRejectsMalformedJWT -fuzztime 5s
	go test ./internal/domain/budget -run '^$$' -fuzz FuzzMoneyDecimal -fuzztime 5s
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
