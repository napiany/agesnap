# Getting started

> [!WARNING]
> Experimental. Do not use it as your only backup.

## Build

```sh
cargo build --release
cp target/release/agesnap ~/.local/bin/agesnap
```

## First repository

Generate an age identity and recipient:

```sh
agesnap keygen \
  --identity-out identity.txt \
  --recipient-out recipient.txt
```

Create the S3 repository metadata:

```sh
agesnap init \
  --repo s3://my-bucket/backups/laptop \
  --s3-endpoint https://s3.eu-central-1.amazonaws.com \
  --s3-region eu-central-1 \
  --recipient "$(cat recipient.txt)" \
  --config-out agesnap.conf \
  --capability-out backup.cap
```

Back up a couple of paths:

```sh
agesnap backup \
  --config agesnap.conf \
  --path /etc \
  --path /home/alice \
  --name laptop \
  --tag laptop
```

List committed snapshots:

```sh
agesnap list --config agesnap.conf
```

Add the identity to show decrypted metadata:

```sh
agesnap list \
  --config agesnap.conf \
  --identity identity.txt
```

Restore the latest snapshot into a new directory:

```sh
agesnap restore \
  --config agesnap.conf \
  --identity identity.txt \
  --snapshot latest \
  --target ./restore
```

Verify stored data:

```sh
agesnap check \
  --config agesnap.conf \
  --identity identity.txt
```

Drop old snapshots, then garbage-collect unreferenced chunks:

```sh
agesnap forget \
  --config agesnap.conf \
  --keep-last 10

agesnap gc \
  --config agesnap.conf \
  --identity identity.txt
```

## Configuration

Example `agesnap.conf`:

```text
agesnap-config-v1

repo.url = s3://my-bucket/backups/laptop
capability.file = ./backup.cap

s3.region = eu-central-1
s3.endpoint = https://s3.eu-central-1.amazonaws.com
s3.path_style = false

chunk.min = 1048576
chunk.avg = 4194304
chunk.max = 16777216

compression.level = 3
metadata.policy = strict
gc.min_age = 7d
```

The config format is plain `key = value` text. Blank lines and `#` comments are
allowed.
