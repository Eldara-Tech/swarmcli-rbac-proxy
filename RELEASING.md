# Release Process

This project uses [GoReleaser](https://goreleaser.com/) for binary releases and Docker Hub for container images.

## Supported Platforms

Binary releases are built for Linux (server component):
- **Linux**: amd64, arm64

Docker images are published to Docker Hub as `eldaratech/swarmcli-rbac-proxy`.

## How to Create a Release

### 1. Create and push a tag

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

GitHub Actions will automatically:
- Create a GitHub release with binary archives (via GoReleaser)
- Build and push a Docker image to Docker Hub
- Generate release notes from PR labels (via release-drafter)

### 2. Verify the release

```bash
# Check GitHub release
gh release view v0.2.0 --repo Eldara-Tech/swarmcli-rbac-proxy

# Check Docker image
docker pull eldaratech/swarmcli-rbac-proxy:0.2.0
docker run --rm eldaratech/swarmcli-rbac-proxy:0.2.0 /proxy --version
```

## Version Information

Version metadata is embedded at build time via ldflags:
- `Version`: Git tag (e.g., `0.2.0`)
- `Commit`: Git commit hash
- `Date`: Build timestamp

These are set in `internal/version/version.go` and injected by both GoReleaser (`.goreleaser.yml`) and the Dockerfile (`--build-arg`).

## Testing Locally

```bash
# Snapshot build (no publish)
goreleaser release --snapshot --clean

# Check built binaries
ls -la dist/

# Docker build with version
docker build \
  --build-arg VERSION=v0.2.0-test \
  --build-arg COMMIT=$(git rev-parse HEAD) \
  --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t swarmcli-rbac-proxy:test .
docker run --rm swarmcli-rbac-proxy:test /proxy --version
```

## Changelog Format

Use conventional commit messages for automatic changelog generation:

- `feat:` — New features
- `fix:` — Bug fixes
- `docs:`, `test:`, `ci:`, `chore:` — Excluded from changelog
