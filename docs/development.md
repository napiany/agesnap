# Development notes

## Dependency policy

Direct dependencies are kept deliberately small:

- `age`
- `blake3`
- `zstd`
- `getrandom`
- `libc`
- `rusty-s3` with `default-features = false`
- `ureq` with `default-features = false` and rustls TLS enabled

`rusty-s3` is used only for Signature V4 signing and request construction.
`ureq` is used only for blocking HTTPS requests and response body reads. The
backend does not use multipart upload or an async runtime.

## Local checks

```sh
cargo test
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
```

## S3 integration checks

Unit tests are not enough for S3 compatibility. Before trusting a backend, test
against real S3 or MinIO:

- `PutObject` with `If-None-Match: *` succeeds for a new object
- the same conditional `PutObject` returns `412 Precondition Failed`
- `412` is treated as a dedupe hit
- `409 ConditionalRequestConflict` is retried
- `ListObjectsV2` pagination works
- `DeleteObject` works for `locks/repo.lock`
- `locks/repo.lock` blocks concurrent `backup`, `forget`, and `gc`
- temporary credentials using `AWS_SESSION_TOKEN` sign requests correctly
