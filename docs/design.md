# Design notes

Backup pipeline:

```text
filesystem
  -> ASAR archive stream
  -> content-defined chunks
  -> keyed BLAKE3 chunk IDs
  -> pack objects
  -> zstd compression
  -> age encryption
  -> S3 objects
```

Restore pipeline:

```text
S3 objects
  -> age decryption
  -> zstd decompression
  -> pack verification
  -> keyed chunk verification
  -> ASAR archive reconstruction
  -> filesystem extraction
```

Out of scope for now: remote indexes, local databases, SSH backends, hosted
services, daemons, and schedulers.

## Restored metadata

`agesnap` restores:

- regular files
- directories
- symlinks
- hardlinks
- mode bits, including executable bits
- uid/gid where the current user can set them
- mtimes

Not handled:

- xattrs
- ACLs
- device nodes
- FIFOs
- sparse file layout

## Archive format

`agesnap` uses a small archive stream format called ASAR v1. The stream has
records for:

- directories
- files
- symlinks
- hardlinks
- end-of-archive marker

File contents are embedded directly in the archive stream. The stream is then
chunked, deduplicated, packed into larger objects, compressed, encrypted, and
uploaded.

Manifests stay small because they store snapshot metadata and the ordered chunk
list with pack IDs, not individual file entries.

## Deduplication

Chunk IDs are keyed BLAKE3 hashes:

```text
chunk_id = BLAKE3_KEYED(chunk_id_key, plaintext_chunk)
```

Raw plaintext hashes are not used as object names. The client can still detect
duplicate chunks, while the storage provider cannot test guessed plaintext
against visible object names.

## Pack objects

Chunks are grouped into immutable encrypted pack objects. The default pack
target is 64 MiB of plaintext chunk data. A local index maps chunk IDs to pack
IDs to avoid repacking known chunks, but restore and check use only encrypted
remote manifests and pack objects.

## Compression

Packs are compressed before encryption with zstd. The default level is `3`.

If compression does not save enough space, the raw pack is stored inside the
encrypted pack object:

```text
if compressed_len + 16 < raw_pack_len:
    store compressed payload
else:
    store raw payload
```
