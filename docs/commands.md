# Commands

## `keygen`

Generate an age identity and recipient:

```sh
agesnap keygen \
  --identity-out identity.txt \
  --recipient-out recipient.txt
```

## `init`

Initialize a new S3 repository:

```sh
agesnap init \
  --repo s3://bucket/prefix \
  --s3-endpoint https://s3.eu-central-1.amazonaws.com \
  --s3-region eu-central-1 \
  --recipient age1... \
  --config-out agesnap.conf \
  --capability-out backup.cap \
  --pack-target 67108864
```

`--pack-target` defaults to `67108864` and must be between `chunk.max` and
256 MiB.

## `backup`

Create a snapshot:

```sh
agesnap backup \
  --config agesnap.conf \
  --path /path/to/back/up \
  --name my-snapshot \
  --tag laptop \
  --spool-dir /var/tmp \
  --index agesnap.conf.index
```

Backup spools each regular file record before feeding it to the chunker. If a
file changes during backup, `agesnap` retries once and then skips that file with
a warning. The spool directory must have enough free space for the largest file
being backed up. Without `--spool-dir`, the system temporary directory is used.
The local chunk-to-pack index defaults to the config path plus `.index`; use
`--index` to override it.

## `list`

List snapshots:

```sh
agesnap list --config agesnap.conf
```

With the age identity, `list` can decrypt snapshot metadata:

```sh
agesnap list \
  --config agesnap.conf \
  --identity identity.txt
```

## `restore`

Restore a snapshot:

```sh
agesnap restore \
  --config agesnap.conf \
  --identity identity.txt \
  --snapshot latest \
  --target ./restore
```

## `check`

Verify repository integrity:

```sh
agesnap check \
  --config agesnap.conf \
  --identity identity.txt
```

## `forget`

Delete old commits and manifests:

```sh
agesnap forget \
  --config agesnap.conf \
  --keep-last 10
```

This does not delete packs.

## `gc`

Delete unreferenced packs:

```sh
agesnap gc \
  --config agesnap.conf \
  --identity identity.txt \
  --min-age 7d
```

Garbage collection requires the age identity because manifests are encrypted.

## `unlock`

Remove a stale repository lock:

```sh
agesnap unlock \
  --config agesnap.conf \
  --force
```

Use this only when no `backup`, `forget`, or `gc` operation is running.
