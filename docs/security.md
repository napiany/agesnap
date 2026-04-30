# Security notes

## Encryption and keys

`agesnap` uses age-compatible public-key encryption.

The source machine needs a backup capability file:

```text
backup.cap
```

The restore machine needs the age identity:

```text
identity.txt
```

The capability file can write encrypted backups, but it cannot decrypt existing
snapshots.

Repository secrets are stored in `secrets.age`, encrypted to the configured age
recipient. They include:

- `repo_id`
- `chunk_id_key`
- `pack_id_key`
- `commit_mac_key`
- `gear_seed`

Those secrets are needed for verification and restore.

## Restore safety

Restore refuses to write outside the target directory. Unsafe archive paths are
rejected, including:

- absolute paths
- empty path components
- `.` components
- `..` components
- path components containing `/`
- path components containing NUL bytes

Existing files are not overwritten unless `--overwrite` is passed.

Symlinks are restored as symlinks. Metadata operations do not follow them.

Selective restore keeps hardlink relationships only when the hardlink target is
also selected. If not, restore fails instead of copying file contents.

### Metadata policy

Restore has two metadata policies: `strict` and `best-effort`. Strict is the
default.

In strict mode, restore fails if required metadata cannot be restored. In
best-effort mode, metadata failures are warnings:

```sh
agesnap restore \
  --config agesnap.conf \
  --identity identity.txt \
  --snapshot latest \
  --target ./restore \
  --metadata best-effort
```

Use `best-effort` when restoring as a non-root user and ownership restore may
fail.

## Disaster recovery

To restore from a fresh machine, keep:

- `agesnap` binary
- `agesnap.conf`, or enough information to recreate the repository config
- `identity.txt`
- S3 read credentials

Then list, check, and restore:

```sh
agesnap list \
  --config agesnap.conf \
  --identity identity.txt

agesnap check \
  --config agesnap.conf \
  --identity identity.txt

agesnap restore \
  --config agesnap.conf \
  --identity identity.txt \
  --snapshot latest \
  --target ./restore
```

The original source machine and `backup.cap` are not needed.

## Threat model

In scope:

- the storage provider reading backup contents
- the storage provider reading filenames or file metadata
- undetected chunk or manifest modification
- accidental object overwrite
- corrupted restore data

Not solved:

- object deletion
- a storage provider hiding newer commits
- a compromised source host writing malicious snapshots
- a stolen backup capability writing new snapshots
- traffic analysis
- pack count and pack size leakage

Bucket versioning, Object Lock, and restricted IAM credentials help with the
cases that are not solved by the file format.
