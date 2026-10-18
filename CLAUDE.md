# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

`wavvon-sdk`: the Rust SDK for [Wavvon](https://github.com/Wavvon) hubs, tier 1 (bots and apps). Apache-2.0.
Contract: <https://github.com/Wavvon/Wavvon-docs/blob/main/docs/sdk.md>. Branch: `develop`.

## Check

`scripts/check` = fmt --check, clippy `-D warnings` (workspace, all targets, all features), tests, docs. CI runs the
same. Run `rustup update stable` first; toolchain skew breaks clippy.

## Layout

- `src/generated/` is progenitor output from Wavvon-docs `openapi.yaml`. **Never edit by hand.** `SPEC_COMMIT` holds
  the docs commit. Regenerate with `cargo xtask generate [docs] [--ref <ref>]`.
- `xtask/` is the generator. It patches the spec in memory and prints each fix: responses without `description`
  and operations without `responses` (progenitor needs both; the latter get a `2XX` because the hub answers 200, 201
  or 204 and the spec does not say which), the undefined `AppRegistration` schema, and multipart operations
  (`POST /channels/{id}/upload`, `POST /soundboard`), which progenitor cannot generate and are dropped. When the
  spec is fixed the matching patch stops applying; delete it then.
- `src/session.rs`: the bearer token shared with the generated client (its pre-hook).
- `src/client.rs`, `src/ws.rs`: session, retry, re-auth, paging, registration, the WebSocket task.
- `src/auth.rs`, `src/webhooks.rs`: the signing primitives. Hand-written on purpose: `wavvon-identity` is AGPL-3.0
  and this crate is Apache-2.0, so it must neither depend on it nor copy its source. Implement from `wire-format.md`.
- `tests/conformance.rs`: byte equality against `wire-vectors.json` (Wavvon-server owns it). Never copy the file in.
- `tests/session_flow.rs`: retry, re-auth and resume against an in-process fake hub.
  `examples/smoke.rs` is the real-hub check.

## Rules

- **Wire formats**: never invent one. A new signed byte sequence needs a server-side change and a vector first.
- **Capabilities, never versions.** A feature needing a string the hub lacks returns `Error::UnsupportedByHub`.
- **Transient is never an answer.** 429, 5xx, timeouts and socket drops end as `Error::Transient`, not `None`,
  empty or false.
- **Unknown is loud.** Unmatched WebSocket types are `Event::Unknown { raw }`; no `_ => {}`.
- **The seed never leaves the process.** No `is_bot`; a program is not a kind of account.
- **Webhook verifiers take the hub key the caller trusts**, never the key named in the request.
- No `#[allow(dead_code)]`; delete what a lint flags. Comments in English, only for a non-obvious why.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Facts that cost time

- The challenge is **hex**: decode it and sign the bytes. The OpenAPI text saying "UTF-8 bytes of the string" is stale.
- `hub_event` and `resume` work only on a socket whose identity had an app profile when it connected: register first.
- The hub answers `app_join` itself; the host side is `app_announce`/`app_dismiss` plus `mini_app_message`.
- The hub never writes `GET /me/events` today; the polling calls follow the spec but nothing here relies on them.
- A fresh hub has no channel; the smoke example creates one.
