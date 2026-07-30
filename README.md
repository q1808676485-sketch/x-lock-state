# GitHub signed-state backend

This directory is mirrored into the public `q1808676485-sketch/x-lock-state` repository. The repository contains only a signed policy, a public key, and the workflow used to update them.

The ES256 private key remains in the public repository's `POLICY_PRIVATE_JWK` Actions secret. `DEVICE_ID` is a repository variable. Every state transition is serialized by workflow concurrency and committed to Git history.

The Android app reads `state.json` through the public GitHub Contents API and uses the HTTPS `Date` response header as the current server-time anchor. It never trusts the phone wall clock for lock expiry.

New locks start with the X, `pornhub.com`, and `xvideos.com` domain families and
common exact Yandex Search entry hosts. They also carry explicit signed matching
rules. The `expand` workflow action can append a plain DNS hostname in `exact`
or `subdomains` mode while an active lock exists. It preserves the lock id,
start time, deadline, and grant and refuses any narrowing transition. Android
independently enforces the same semantic-superset rule. All entries share the
same deadline and temporary grant.
