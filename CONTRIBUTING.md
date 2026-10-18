# Contributing

- Work on a branch off `develop`; squash-merge into `develop`.
- `scripts/check` must pass.
- Generated code changes only through `cargo xtask generate` (use `--ref` so `SPEC_COMMIT` is a real commit).
- A signing or wire change starts in Wavvon-server with a vector in `wire-vectors.json`; this repo then asserts it.
- Comments in English, explaining only what the code cannot. New behaviour needs a test; a refusal needs a rejection test.
- Commit messages in English.
