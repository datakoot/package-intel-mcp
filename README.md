# Package Intel MCP — by Datakoot

Software supply-chain intelligence for AI agents — as MCP tools your agent can call mid-task, so it can vet a dependency *before* it installs it. Covers npm, PyPI and crates.io. No API keys.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `package_info` | Metadata for a package: description, latest version, license, homepage & repo links | npm / PyPI / crates.io |
| `package_versions` | Full version history with release dates | npm / PyPI / crates.io |
| `package_downloads` | Download counts and popularity signal | npm / PyPI / crates.io |
| `package_dependencies` | Direct dependencies for a given version | deps.dev |
| `package_health` | Health signals: OpenSSF Scorecard, stars, dependents | deps.dev |
| `package_search` | Search for packages by keyword | npm / PyPI / crates.io |

Every tool accepts an `ecosystem` of `npm`, `pypi`, or `crates`. No API keys required.

## Quick start

```
claude mcp add --transport http package-intel https://package.datakoot.com/mcp
```

Or point any MCP client at `https://package.datakoot.com/mcp`.

## Data & attribution

Data comes from the public registry APIs for [npm](https://registry.npmjs.org), [PyPI](https://pypi.org) and [crates.io](https://crates.io), plus [deps.dev](https://deps.dev) (Google Open Source Insights, CC-BY 4.0) for dependency graphs and OpenSSF Scorecard health signals. Package data is served from official public APIs and is informational.

Part of [Datakoot](https://datakoot.com) — keyless intelligence APIs for AI agents.
