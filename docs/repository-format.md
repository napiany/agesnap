# Repository format

An `agesnap` repository is an S3 object tree:

```text
config.txt
secrets.age
chunks/<prefix>/<chunk_id>.age
manifests/<prefix>/<snapshot_id>.manifest.age
commits/<unix_nanos>-<snapshot_id>.commit
locks/repo.lock
```

Each chunk is a separate encrypted object. Snapshot manifests are encrypted too.
A snapshot becomes visible only when its commit object has been written.

`locks/repo.lock` serializes `backup`, `forget`, and `gc`. Without that lock,
GC could delete an old unreferenced chunk while a backup is reusing it as a
dedupe hit. If a process crashes with the lock held, confirm no `backup`,
`forget`, or `gc` is still running, then use `agesnap unlock --force`.

## S3 behavior

`agesnap` uses a small subset of S3: single-object put/get/delete, ListObjectsV2,
and conditional writes. `rusty-s3` builds and signs AWS Signature V4 requests;
`ureq` sends blocking HTTPS requests using rustls.

Repository config carries the S3 connection details:

```text
repo.url=s3://my-bucket/agesnap/laptop
s3.endpoint=https://s3.eu-central-1.amazonaws.com
s3.region=eu-central-1
s3.path_style=false
```

The repository prefix must leave room for generated object names inside S3's
1,024-byte object-key limit. Non-empty prefixes are limited to 923 UTF-8 bytes.

For writes, it uses conditional object creation:

```text
If-None-Match: *
```

S3 accepts the write only if the object does not already exist.

For chunks, that is both the immutable write and the dedupe check:

```text
upload chunk object
if object already exists:
    treat as dedupe hit
```

Transport failures are retried with the same chunk key. If the first attempt
actually committed, the retry gets `412 Precondition Failed` and treats the
chunk as uploaded. `409 ConditionalRequestConflict` is retried with backoff.
Multipart upload is intentionally not used.

Listings use `ListObjectsV2` with `encoding-type=url`, then percent-decode
returned object keys. This avoids XML parser differences for valid S3 keys that
are awkward to represent directly in XML.

Resumability is chunk-object based. A crashed backup may leave orphan chunks,
orphan manifests, or a stale lock. A snapshot is visible only after its commit
object is written. After a stale lock is removed, the next backup rebuilds the
archive stream and reuses existing chunks through `If-None-Match: *`. Garbage
collection removes unreferenced chunks and orphan manifests only after the grace
period, default `7d`.

## Credentials

Recommended bucket setup:

- enable bucket versioning
- use Object Lock if your provider supports it
- use separate credentials for backup and administration
- deny delete permissions to backup-only credentials

Backup credentials normally need:

- `s3:PutObject`
- `s3:GetObject`
- `s3:ListBucket`
- `s3:DeleteObject` for `locks/repo.lock`

Backup credentials should not be able to delete:

- `chunks/*`
- `manifests/*`
- `commits/*`

Administrative credentials are needed for `forget`, `gc`, and
`unlock --force`.
