# govulnfix

`govulnfix` is a CLI that iteratively updates `go.mod` until all Go
vulnerabilities reported by
[`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) and
[GitHub Dependabot alerts](https://docs.github.com/en/code-security/dependabot)
are resolved.

## How it works

1. Runs `govulncheck -json ./...` against the target module.
2. Fetches open Dependabot Go ecosystem alerts from the GitHub API.
3. Merges the two sources into a deduplicated set of `go get` upgrade targets.
4. Applies `go get <module>@<version>` for each target, then `go mod tidy`.
5. Repeats until no vulnerabilities remain or `--max-iterations` is reached.

## Prerequisites

- Go toolchain with `govulncheck` installed (`go install golang.org/x/vuln/cmd/govulncheck@latest`)
- A GitHub personal access token (or fine-grained token) with **read** access to Dependabot alerts (`security_events` scope for classic tokens)

## Installation

```sh
go install github.com/appscodelabs/govulnfix@latest
```

## Usage

```
govulnfix [flags]

Flags:
  --dir string            Path to the Go module to update (default: current directory)
  --repo string           GitHub repository in owner/repo form
                          (defaults to GITHUB_REPOSITORY env var or the origin remote)
  --github-token string   GitHub token for Dependabot alerts
                          (defaults to GITHUB_TOKEN, then GH_TOOLS_TOKEN)
  --pattern strings       Package patterns passed to govulncheck (default: [./...])
  --max-iterations int    Maximum remediation passes to attempt (default: 10)
  --dry-run               Print planned upgrades without modifying go.mod
```

### Examples

Fix vulnerabilities in the current directory, inferring the repo from `git remote`:

```sh
export GITHUB_TOKEN=ghp_...
govulnfix
```

Target a specific module directory and repository:

```sh
govulnfix --dir ./myservice --repo myorg/myservice --github-token ghp_...
```

Preview the planned upgrades without making any changes:

```sh
govulnfix --dry-run
```

## GitHub repository detection

The `--repo` flag is resolved in the following order:

1. `--repo` flag value
2. `GITHUB_REPOSITORY` environment variable
3. `origin` remote URL parsed as a GitHub HTTPS or SSH URL
4. Any other `git remote` URL that points to GitHub

## Token detection

The `--github-token` flag is resolved in the following order:

1. `--github-token` flag value
2. `GITHUB_TOKEN` environment variable
3. `GH_TOOLS_TOKEN` environment variable

## License

[Apache 2.0](LICENSE)
