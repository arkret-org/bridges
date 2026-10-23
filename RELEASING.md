# Tag releases

Pushing a `v*` tag builds and publishes a GitHub Release after every required
build succeeds. `workflow_dispatch` builds the same artifacts without publishing
a release; use it before tagging. Existing source versions are not changed.

Sibling checkout revisions in the workflow are part of the release source set.
Before tagging, update those pins to a compatible tested set and commit any
required Cargo.lock changes. Do not replace pinned revisions with `main`. Each
archive includes `build-info.json` with the source commits and lockfile hash,
and a companion SHA-256 file. Verify it from the download directory with
`sha256sum --check ./*.sha256`.

Cross-repository private dependencies require `CI_REPO_TOKEN` with read access;
`GITHUB_TOKEN` only supplies the current repository's permissions. Publishing
uses the release job's `contents: write` permission.

Each platform archive contains all fourteen bridge executables. Targets are
Linux x64/ARM64, Windows x64 and macOS ARM64. Linux builds target Ubuntu 24.04
(glibc 2.39 or newer). Provider credentials and configuration are supplied by
the operator. The container job also publishes Linux amd64/arm64 images for
each bridge on a tag; it must succeed before the GitHub Release is created.

Release containers reuse the checked and checksummed Linux binaries from the
platform build jobs, with an Ubuntu 24.04 runtime matching their glibc baseline.
They do not recompile Rust once per bridge or architecture.

The archives include `config/<bridge>.yaml` provider configuration samples.
Checksummed source SBOMs are attached by the final release job; image jobs do
not independently modify GitHub releases.
