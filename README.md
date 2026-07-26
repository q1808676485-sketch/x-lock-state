# GitHub signed-state backend

This directory is mirrored into the public `q1808676485-sketch/x-lock-state` repository. The repository contains only a signed policy, a public key, and the workflow used to update them.

The ES256 private key remains in the public repository's `POLICY_PRIVATE_JWK` Actions secret. `DEVICE_ID` is a repository variable. Every state transition is serialized by workflow concurrency and committed to Git history.

The Android app reads `state.json` through the public GitHub Contents API and uses the HTTPS `Date` response header as the current server-time anchor. It never trusts the phone wall clock for lock expiry.
