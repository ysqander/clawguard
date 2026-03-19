# Release Checklist

This checklist is the human-facing release runbook for ClawGuard.

The automated release workflow in [`.github/workflows/release.yml`](../.github/workflows/release.yml) publishes on a `v*` tag, but this checklist is the last manual review before pushing that tag.

## Preflight

- Confirm `main` is clean:

```bash
git status --short
```

- Confirm the version in [`package.json`](../package.json) is correct for the release.
- Confirm the README and release notes match the shipped CLI surface and caveats.

## Validation

Run the full release gate:

```bash
pnpm release:check
```

This must pass before tagging.

Optional additional validation:

```bash
pnpm bench:static:ci
pnpm bench:detonation:preflight
```

## Packaging

Build the publishable tarball locally:

```bash
pnpm release:pack
```

Sanity-check that a tarball exists:

```bash
ls .release/*.tgz
```

## Release Notes

- Review [`docs/releases/0.1.0.md`](./releases/0.1.0.md).
- Make sure the highlights, caveats, and install instructions still match the current build.

## Tag And Publish

Create and push the release tag that matches the package version:

```bash
git tag v0.1.0
git push origin main
git push origin v0.1.0
```

The GitHub Actions workflow will then:

- run `pnpm release:check`
- publish the packed tarball to npm
- create the GitHub release

## Post-Publish

- Confirm the npm package is available:

```bash
npm view clawguard version
```

- Confirm the GitHub release exists and includes the packed tarball asset.
- Confirm a clean-machine install still works:

```bash
npm install -g clawguard
clawguard status
```

## Current Release Scope Notes

- macOS-first operator flow is supported.
- Podman is the default detonation runtime.
- Docker is the compatibility runtime and was exercised during signoff.
- ClawHub and VirusTotal are enrichment signals, not proof of safety.
- Behavioral detonation reduces risk but does not prove safety.
