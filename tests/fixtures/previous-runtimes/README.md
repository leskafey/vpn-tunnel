# Historical runtime fixtures

These files are exact snapshots of `src/vpn-stack-runtime.py` from the commits
listed in `manifest.json`. They contain source code, not installation data.

`test_upgrade_review.py` checks their SHA-256 and executes each historical lock
before and after publishing an upgrade fence. The snapshots keep this regression
test independent of Git history, including shallow checkouts and source archives
after an amend or squash removes a commit from the published branch.

Preserve the snapshots unchanged. To test another historical runtime, add a new
snapshot and record its full commit, source path and SHA-256 in the manifest.
These fixtures do not provide the full packages used by the native Linux tests;
those scenarios still require the historical archives described in DEVELOPMENT.md.
