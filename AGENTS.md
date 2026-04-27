# Contributor notes

Working notes for this repository. Keep changes small, local, and easy to
review.

## Project shape

`agesnap` is a Rust backup tool with a narrow scope:

- ASAR archive stream
- Gear content-defined chunking
- keyed BLAKE3 chunk IDs and commit MACs
- zstd compression
- age-compatible encryption
- S3-only storage
- restore with permissions, symlinks, hardlinks, uid/gid, and mtime

## Scope boundaries

Repository object layout:

```text
config.txt
secrets.age
chunks/<prefix>/<chunk_id>.age
manifests/<prefix>/<snapshot_id>.manifest.age
commits/<unix_nanos>-<snapshot_id>.commit
locks/repo.lock
```

## Safety invariants

- Backup does not require an age identity.
- Restore and GC require an age identity.
- Backup, forget, and GC use `locks/repo.lock`.
- If a process crashes while holding the lock, `unlock --force` is only safe
  after confirming no `backup`, `forget`, or `gc` is running.
- Use S3 `PutObject` with `If-None-Match: *` for immutable writes.
- Do not emulate immutable writes with a prior `HeadObject`; rely on the S3
  conditional write result.
- Treat `412 Precondition Failed` from conditional `PutObject` as a dedupe hit.
- Retry `409 ConditionalRequestConflict` and 5xx/transport failures with
  backoff.
- Use `ListObjectsV2` with `encoding-type=url`, and percent-decode returned
  keys before stripping the repository prefix.
- Keep generated S3 keys within the 1,024-byte object-key limit.
- Write commit objects last.
- Validate manifest fields before encode so the writer cannot commit snapshots
  the parser later rejects.
- Verify keyed chunk IDs after decrypting and decompressing chunks.
- Backup directory traversal must stay fd-relative after the root directory is
  opened. Use `openat`/`fstatat` style helpers with `O_NOFOLLOW`; do not
  reintroduce pathname recursion through `fs::read_dir` and `entry.path()`.
- Never write outside the restore target.
- Never follow symlinks while restoring metadata.
- Do not overwrite restore targets unless `--overwrite` is passed.
- For restore overwrite, create regular files, symlinks, and hardlinks under a
  temporary name first, then rename over the final path. Do not unlink the
  existing target before replacement succeeds.
- Clean up `.agesnap-tmp-*` restore files/links on failed placement.
- Selective restore of hardlinks may fail when the hardlink target was not
  selected; do not silently copy file contents.

## S3 compatibility

Use only the boring S3 subset:

- `PutObject`
- `GetObject`
- `DeleteObject`
- `ListObjectsV2`
- conditional writes with `If-None-Match: *`
- AWS Signature V4 through `rusty-s3`
- blocking HTTPS through `ureq`

## Development commands

```bash
cargo test
```

Formatting and linting use the local Cargo aliases:

```bash
rustup component add rustfmt clippy && cargo fmtcheck && cargo lint'
```

For Rust changes, run `cargo fmt` before handing off. Run `cargo test` for code
changes, and run the fmtcheck/lint command before final handoff when practical.

S3 behavior still needs integration testing against real S3 or MinIO for:

- conditional put success and `412` dedupe
- `409` retry behavior
- `ListObjectsV2` pagination and `encoding-type=url`
- delete of `locks/repo.lock`
- lock exclusion across `backup`, `forget`, and `gc`
- temporary credentials with `AWS_SESSION_TOKEN`
