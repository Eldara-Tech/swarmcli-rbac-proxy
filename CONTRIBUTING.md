# Contributing

Thanks for your interest in contributing to swarm-rbac-proxy.

## Getting started

```bash
go build .
go test -v -race ./...
gofmt -l .
go vet ./...
golangci-lint run
```

Integration tests require a PostgreSQL instance:

```bash
TEST_DATABASE_URL=postgres://user:pass@localhost:5432/testdb?sslmode=disable \
  go test -race -tags=integration ./...
```

See [CLAUDE.md](CLAUDE.md) for full architecture details and the pre-push checklist.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Make your changes. Keep diffs focused — one concern per PR.
3. Ensure all checks pass: `go build . && go test -race ./... && gofmt -l . && go vet ./... && golangci-lint run`
4. If you add new environment variables, endpoints, or CLI commands, update the relevant docs (`docs/configuration.md`, `docs/api.md`, `CLAUDE.md`).
5. Open a pull request with a clear description of what and why.

## Reporting issues

Use the [GitHub issue tracker](https://github.com/Eldara-Tech/swarmcli-rbac-proxy/issues).
