# Security policy

`agesnap` is pre-1.0 backup software. Treat it as experimental, and test
restores before trusting it with data.

## Reporting

Do not post exploit details in a public issue, discussion, or pull request.

Use private vulnerability reporting if it is enabled on the current forge. If
not, contact the maintainer out of band before publishing details.

Useful reports include:

- what went wrong and why it matters
- reproduction steps
- affected commit, tag, or release
- relevant config, command lines, and S3 provider details
- logs or proof-of-concept code, with private data removed
- a proposed fix, if you have one

I cannot promise fixed response times for a small experimental project. I will
handle credible security reports as quickly as I can.

## Supported code

Only the latest public code is considered supported for security fixes.

| Version | Supported |
|---|---|
| latest `main` / latest release | Yes |
| older commits and releases | No |

## In scope

- separation between `backup.cap` and the age identity
- repository secret handling
- encryption, decryption, MAC, keyed pack, or keyed chunk verification bugs
- restore path traversal
- symlink handling during restore or metadata restore
- unsafe overwrite behavior
- hardlink, permission, uid/gid, or mtime handling with security impact
- S3 immutable writes, especially `If-None-Match: *`
- commit, manifest, pack, or chunk tampering that passes verification
- data corruption that passes `check`
- credential leakage in output, logs, errors, config, or object names
- dependency issues with a demonstrated `agesnap` impact

## Out of scope

- vulnerabilities in S3 services themselves
- vulnerabilities in age, BLAKE3, zstd, rustls, or other dependencies without
  an `agesnap` exploit path
- denial of service without a security impact
- social engineering or phishing
- attacks requiring malicious local root access
- unverified scanner output

## Security model

- backup uses `backup.cap` and does not need the age identity
- restore, check, and garbage collection require the age identity
- repository secrets live in `secrets.age`
- repository secrets are `repo_id`, `chunk_id_key`, `pack_id_key`,
  `commit_mac_key`, and `gear_seed`
- pack names are keyed BLAKE3 IDs, not raw plaintext hashes
- packs and chunks are verified after decryption and decompression
- commit objects are MACed and written last
- immutable writes use S3 `PutObject` with `If-None-Match: *`
- restore rejects unsafe paths
- restore does not overwrite targets unless `--overwrite` is passed
- restore metadata operations do not follow symlinks

More detail:

- [docs/security.md](docs/security.md)
- [docs/repository-format.md](docs/repository-format.md)

## Disclosure

Give me a reasonable chance to investigate and fix the issue before publishing
details. I may ask for more information if I cannot reproduce the report. If a
fix ships, I will credit the reporter unless they prefer not to be named.

## Safe harbor

Good-faith research against systems and repositories you own is welcome.

Do not access, change, delete, or disclose anyone else's data. Do not test
against buckets, accounts, machines, or networks you do not control. If you hit
private data by accident, stop and report the issue without sharing the data.

## User checklist

1. Test restore before trusting any backup.
2. Keep `identity.txt` off backup-only machines.
3. Protect `backup.cap`; it can write snapshots.
4. Use separate S3 credentials for backup and administration.
5. Deny delete permissions to backup-only credentials except for
   `locks/repo.lock`.
6. Enable bucket versioning, and Object Lock if your provider supports it.
7. Store `identity.txt` and repository config away from the source machine.
8. Run `agesnap check` periodically.
9. Keep `agesnap` and dependencies updated.
