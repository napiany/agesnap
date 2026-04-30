# agesnap

`agesnap` stores age-encrypted, compressed, deduplicated snapshots in
S3-compatible object storage.

> [!WARNING]
> Experimental. Do not use it as your only backup.

It walks one or more filesystem roots, writes an ASAR archive stream, splits the
stream with content-defined chunking, packs chunks into larger objects,
compresses each pack with zstd, encrypts it with age, and uploads the result to
S3.

The general idea is close to [Tarsnap](https://www.tarsnap.com/): client-side
encrypted, deduplicated online backups. `agesnap` is independent from Tarsnap
and uses storage you provide.

## AI-assisted development

I use AI-assisted tools while working on this project: completion, review
prompts, security checklists, and documentation drafts. I still own the design,
the code that lands, and the tests.

If that does not fit what you want from backup software, use something more
established, such as Tarsnap, BorgBackup, or restic.

## Documentation

- [Getting started](docs/getting-started.md): first repository and restore
- [Commands](docs/commands.md): command reference
- [Design](docs/design.md): archive stream, chunking, encryption
- [Repository format](docs/repository-format.md): object layout and S3 behavior
- [Security](docs/security.md): keys, restore safety, recovery notes
- [Development](docs/development.md): dependency policy and checks

## Build

```sh
cargo build --release
cp target/release/agesnap ~/.local/bin/agesnap
```
