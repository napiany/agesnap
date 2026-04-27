use age::secrecy::ExposeSecret;
use age::x25519;
use getrandom::fill as fill_random_bytes;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const DEFAULT_MIN_CHUNK: u32 = 1 << 20;
const DEFAULT_TARGET_CHUNK: u32 = 4 << 20;
const DEFAULT_MAX_CHUNK: u32 = 16 << 20;
const DEFAULT_ZSTD_LEVEL: i32 = 3;
const DEFAULT_GC_MIN_AGE_SECS: u64 = 7 * 24 * 60 * 60;
const S3_SIGNED_URL_TTL_SECS: u64 = 15 * 60;
const S3_MAX_READ_BYTES: u64 = 512 * 1024 * 1024;
const S3_MAX_OBJECT_KEY_BYTES: usize = 1024;
const MAX_GENERATED_S3_KEY_BYTES: usize = 8 + 20 + 1 + 64 + 7;
const MAX_PATH_COMPONENT_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 1024;
const MAX_SYMLINK_TARGET_BYTES: usize = 1024 * 1024;
const MAX_CHUNK_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST_TEXT_BYTES: usize = 4096;
const MAX_MANIFEST_TAGS: usize = 1024;
const MAX_MANIFEST_CHUNKS: usize = 1_000_000;

const ASAR_MAGIC: &[u8; 8] = b"ASAR01\0\0";
const CHUNK_MAGIC: &[u8; 8] = b"ASCHK01\0";
const MANIFEST_MAGIC: &[u8; 8] = b"ASMAN01\0";

const REC_DIR: u8 = 1;
const REC_FILE: u8 = 2;
const REC_SYMLINK: u8 = 3;
const REC_HARDLINK: u8 = 4;
const REC_END: u8 = 255;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("agesnap: {e}");
        let code = e.downcast_ref::<ExitError>().map_or(1, |e| e.code);
        std::process::exit(code);
    }
}

fn real_main() -> Result<()> {
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() || args[0] == OsStr::new("-h") || args[0] == OsStr::new("--help") {
        print_usage();
        return Ok(());
    }

    let command = os_string_to_string(args.remove(0), "command")?;
    match command.as_str() {
        "keygen" => cmd_keygen(args),
        "init" => cmd_init(args),
        "backup" => cmd_backup(args),
        "list" => cmd_list(args),
        "restore" => cmd_restore(args),
        "check" => cmd_check(args),
        "forget" => cmd_forget(args),
        "unlock" => cmd_unlock(args),
        "gc" => cmd_gc(args),
        _ => err(format!("unknown command: {command}")),
    }
}

fn print_usage() {
    eprintln!(
        "usage: agesnap <command> [options]

commands:
  keygen
      --identity-out identity.txt --recipient-out recipient.txt
  init
      --repo s3://bucket/prefix --s3-endpoint URL --s3-region REGION
      --recipient AGE_RECIPIENT --config-out agesnap.conf --capability-out backup.cap
  backup
      --config agesnap.conf [--path ROOT]... [--name NAME] [--tag TAG]
      [--spool-dir DIR] [ROOT...]
  list
      --config agesnap.conf [--identity identity.txt]
  restore
      --config agesnap.conf --identity identity.txt --snapshot latest|ID --target DIR
      [--path ARCHIVE_PATH]... [--overwrite] [--metadata strict|best-effort]
  check
      --config agesnap.conf --identity identity.txt [--snapshot latest|ID]
  forget
      --config agesnap.conf --keep-last N
  unlock
      --config agesnap.conf --force
  gc
      --config agesnap.conf --identity identity.txt [--delete] [--min-age 7d]"
    );
}

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(message.into().into())
}

fn err_code<T>(code: i32, message: impl Into<String>) -> Result<T> {
    Err(Box::new(ExitError {
        code,
        message: message.into(),
    }))
}

#[derive(Debug)]
struct ExitError {
    code: i32,
    message: String,
}

impl std::fmt::Display for ExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExitError {}

#[derive(Clone, Debug, Default)]
struct S3ClientOptions {
    region: Option<String>,
    endpoint: Option<String>,
    path_style: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataPolicy {
    Strict,
    BestEffort,
}

impl MetadataPolicy {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "strict" => Ok(Self::Strict),
            "best-effort" => Ok(Self::BestEffort),
            _ => err(format!("invalid metadata policy: {value}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::BestEffort => "best-effort",
        }
    }

    fn handle(self, operation: &str, result: Result<()>) -> Result<()> {
        match result {
            Ok(()) => Ok(()),
            Err(e) if self == Self::BestEffort => {
                eprintln!("agesnap: warning: {operation} failed: {e}");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone, Debug)]
struct LocalConfig {
    repo: S3Repo,
    capability: Option<PathBuf>,
    s3: S3ClientOptions,
    metadata_policy: MetadataPolicy,
    compression_level: i32,
    min_chunk: u32,
    target_chunk: u32,
    max_chunk: u32,
    gc_min_age_secs: u64,
}

impl LocalConfig {
    fn default_for_repo(repo: S3Repo) -> Self {
        Self {
            repo,
            capability: None,
            s3: S3ClientOptions::default(),
            metadata_policy: MetadataPolicy::Strict,
            compression_level: DEFAULT_ZSTD_LEVEL,
            min_chunk: DEFAULT_MIN_CHUNK,
            target_chunk: DEFAULT_TARGET_CHUNK,
            max_chunk: DEFAULT_MAX_CHUNK,
            gc_min_age_secs: DEFAULT_GC_MIN_AGE_SECS,
        }
    }

    fn encode(&self) -> Result<String> {
        let mut out = String::new();
        out.push_str("agesnap-config-v1\n");
        out.push_str(&format!("repo.url={}\n", self.repo));
        if let Some(path) = &self.capability {
            out.push_str(&format!(
                "capability.file={}\n",
                path_to_config_value(path)?
            ));
        }
        if let Some(region) = &self.s3.region {
            out.push_str(&format!("s3.region={region}\n"));
        }
        if let Some(endpoint) = &self.s3.endpoint {
            out.push_str(&format!("s3.endpoint={endpoint}\n"));
        }
        out.push_str(&format!("s3.path_style={}\n", self.s3.path_style));
        out.push_str(&format!(
            "metadata.policy={}\n",
            self.metadata_policy.as_str()
        ));
        out.push_str(&format!("compression.level={}\n", self.compression_level));
        out.push_str(&format!("chunk.min={}\n", self.min_chunk));
        out.push_str(&format!("chunk.avg={}\n", self.target_chunk));
        out.push_str(&format!("chunk.max={}\n", self.max_chunk));
        out.push_str(&format!(
            "gc.min_age={}\n",
            format_duration_secs(self.gc_min_age_secs)
        ));
        Ok(out)
    }

    fn parse(text: &str) -> Result<Self> {
        let kv = KeyValues::parse(text, "agesnap-config-v1")?;
        kv.reject_unknown(&[
            "repo.url",
            "capability.file",
            "s3.region",
            "s3.endpoint",
            "s3.path_style",
            "metadata.policy",
            "compression.level",
            "chunk.min",
            "chunk.avg",
            "chunk.max",
            "gc.min_age",
        ])?;
        let repo = S3Repo::parse(kv.required("repo.url")?)?;
        let mut config = Self::default_for_repo(repo);
        config.capability = kv.optional("capability.file").map(PathBuf::from);
        config.s3.region = kv.optional("s3.region").map(ToOwned::to_owned);
        config.s3.endpoint = kv.optional("s3.endpoint").map(ToOwned::to_owned);
        if let Some(value) = kv.optional("s3.path_style") {
            config.s3.path_style = parse_bool(value)?;
        }
        if let Some(value) = kv.optional("metadata.policy") {
            config.metadata_policy = MetadataPolicy::parse(value)?;
        }
        if let Some(value) = kv.optional("compression.level") {
            config.compression_level = parse_compression_level(value)?;
        }
        if let Some(value) = kv.optional("chunk.min") {
            config.min_chunk = value.parse()?;
        }
        if let Some(value) = kv.optional("chunk.avg") {
            config.target_chunk = value.parse()?;
        }
        if let Some(value) = kv.optional("chunk.max") {
            config.max_chunk = value.parse()?;
        }
        if let Some(value) = kv.optional("gc.min_age") {
            config.gc_min_age_secs = parse_duration_secs(value)?;
        }
        validate_chunk_settings(config.min_chunk, config.target_chunk, config.max_chunk)?;
        Ok(config)
    }

    fn read(path: &Path) -> Result<Self> {
        Self::parse(&read_to_string(path)?)
    }
}

struct LoadedLocalConfig {
    path: PathBuf,
    config: LocalConfig,
}

impl LoadedLocalConfig {
    fn capability_path(&self) -> Option<PathBuf> {
        self.config
            .capability
            .as_ref()
            .map(|path| resolve_config_path(&self.path, path))
    }
}

fn cmd_keygen(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let identity_path = match p.value_path("--identity-out") {
        Some(path) => path,
        None => p.required_path("--identity")?,
    };
    let recipient_path = p.value_path("--recipient-out");
    p.finish()?;

    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    let secret = identity.to_string();
    write_private_file(
        &identity_path,
        format!("{}\n", secret.expose_secret()).as_bytes(),
        false,
    )?;
    if let Some(path) = recipient_path {
        write_public_file(&path, format!("{recipient}\n").as_bytes(), false)?;
    }
    println!("{recipient}");
    Ok(())
}

fn cmd_init(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let repo = S3Repo::parse(&p.required_value("--repo")?)?;
    let recipients = p.values("--recipient")?;
    let capability_path = p
        .value_path("--capability-out")
        .or_else(|| p.value_path("--capability"))
        .unwrap_or_else(|| PathBuf::from("backup.cap"));
    let config_path = p.value_path("--config-out");
    let overwrite_capability = p.flag("--overwrite-capability");
    let overwrite_config = p.flag("--overwrite-config");
    let mut local_config = LocalConfig::default_for_repo(repo.clone());
    apply_s3_args(&mut p, &mut local_config.s3)?;
    if let Some(value) = p.value("--metadata")? {
        local_config.metadata_policy = MetadataPolicy::parse(&value)?;
    }
    if let Some(value) = p.value("--compression-level")? {
        local_config.compression_level = parse_compression_level(&value)?;
    }
    if let Some(value) = p.value("--chunk-min")? {
        local_config.min_chunk = value.parse()?;
    }
    if let Some(value) = p.value("--chunk-avg")? {
        local_config.target_chunk = value.parse()?;
    }
    if let Some(value) = p.value("--chunk-max")? {
        local_config.max_chunk = value.parse()?;
    }
    validate_chunk_settings(
        local_config.min_chunk,
        local_config.target_chunk,
        local_config.max_chunk,
    )?;
    local_config.capability = Some(if config_path.is_some() {
        absolutize_path(&capability_path)?
    } else {
        capability_path.clone()
    });
    p.finish()?;

    if recipients.is_empty() {
        return err("init requires at least one --recipient");
    }
    let parsed_recipients = parse_recipients(&recipients)?;

    let mut repo_id = [0u8; 32];
    let mut chunk_id_key = [0u8; 32];
    let mut commit_mac_key = [0u8; 32];
    let mut gear_seed = [0u8; 32];
    fill_random(&mut repo_id)?;
    fill_random(&mut chunk_id_key)?;
    fill_random(&mut commit_mac_key)?;
    fill_random(&mut gear_seed)?;

    let public_config = PublicConfig {
        repo_id,
        created_unix_ns: unix_nanos()?,
        min_chunk: local_config.min_chunk,
        target_chunk: local_config.target_chunk,
        max_chunk: local_config.max_chunk,
    };
    let secrets = RepoSecrets {
        repo_id,
        chunk_id_key,
        commit_mac_key,
        gear_seed,
    };
    let capability = Capability {
        repo: repo.clone(),
        repo_id,
        recipients,
        min_chunk: local_config.min_chunk,
        target_chunk: local_config.target_chunk,
        max_chunk: local_config.max_chunk,
        compression_level: local_config.compression_level,
        chunk_id_key,
        commit_mac_key,
        gear_seed,
    };
    let local_config_text = match &config_path {
        Some(_) => Some(local_config.encode()?),
        None => None,
    };
    let prepared_capability = PreparedPrivateFile::create(
        &capability_path,
        capability.encode().as_bytes(),
        overwrite_capability,
    )?;
    let prepared_config = match &config_path {
        Some(path) => match PreparedPublicFile::create(
            path,
            local_config_text
                .as_ref()
                .expect("config text exists")
                .as_bytes(),
            overwrite_config,
        ) {
            Ok(file) => Some(file),
            Err(e) => {
                prepared_capability.discard();
                return Err(e);
            }
        },
        None => None,
    };

    let secrets_ciphertext = match age_encrypt(&parsed_recipients, secrets.encode().as_bytes()) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            prepared_capability.discard();
            if let Some(file) = &prepared_config {
                file.discard();
            }
            return Err(e);
        }
    };

    let client = s3_client(&repo, &local_config.s3)?;
    if let Err(e) = put_immutable_new(
        &client,
        &repo,
        "config.txt",
        public_config.encode().into_bytes(),
    ) {
        prepared_capability.discard();
        if let Some(file) = &prepared_config {
            file.discard();
        }
        return Err(e);
    }

    match put_immutable(&client, &repo, "secrets.age", secrets_ciphertext) {
        Ok(true) => {}
        Ok(false) => {
            let cleanup_result = s3_delete_any(&client, &repo, "config.txt");
            prepared_capability.discard();
            if let Some(file) = &prepared_config {
                file.discard();
            }
            return init_failed(
                "immutable object already exists: secrets.age",
                cleanup_result,
            );
        }
        Err(e) => {
            let cleanup_result =
                rollback_init_objects(&client, &repo, &["secrets.age", "config.txt"]);
            prepared_capability.discard();
            if let Some(file) = &prepared_config {
                file.discard();
            }
            return init_failed(e, cleanup_result);
        }
    }
    if let Err(e) = prepared_capability.commit() {
        let cleanup_result = rollback_init_objects(&client, &repo, &["secrets.age", "config.txt"]);
        prepared_capability.discard();
        if let Some(file) = &prepared_config {
            file.discard();
        }
        return init_failed(e, cleanup_result);
    }
    if let Some(file) = prepared_config
        && let Err(e) = file.commit()
    {
        let cleanup_result = rollback_init_objects(&client, &repo, &["secrets.age", "config.txt"]);
        return init_failed(e, cleanup_result);
    }

    println!("initialized {}", repo);
    println!(
        "wrote local backup capability: {}",
        capability_path.display()
    );
    if let Some(path) = config_path {
        println!("wrote local config: {}", path.display());
    }
    Ok(())
}

fn init_failed<T>(primary: impl std::fmt::Display, cleanup: Result<()>) -> Result<T> {
    match cleanup {
        Ok(()) => err(primary.to_string()),
        Err(cleanup) => err(format!("{primary}; rollback failed: {cleanup}")),
    }
}

fn cmd_backup(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let cap_path = capability_path_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let compression_override = if let Some(value) = p.value("--compression-level")? {
        parse_compression_level(&value)?
    } else {
        loaded_config
            .as_ref()
            .map_or(-1, |loaded| loaded.config.compression_level)
    };
    let name = p.value_os("--name").unwrap_or_default();
    let tags = p.values_os("--tag");
    let mut roots: Vec<PathBuf> = p
        .values_os("--path")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let spool_dir = p
        .value_path("--spool-dir")
        .unwrap_or_else(std::env::temp_dir);
    roots.extend(p.rest_paths());
    p.finish()?;

    if roots.is_empty() {
        return err("backup requires at least one root path");
    }

    let capability = Capability::parse(&read_to_string(&cap_path)?)?;
    if capability.repo != repo {
        return err("capability repo does not match --repo");
    }
    let recipients = parse_recipients(&capability.recipients)?;
    let compression_level = if compression_override >= 0 {
        compression_override
    } else {
        capability.compression_level
    };
    let client = s3_client(&repo, &s3_options)?;
    let public_config = fetch_public_config(&client, &repo)?;
    if public_config.repo_id != capability.repo_id {
        return err("repository config does not match capability");
    }

    let request = BackupRequest {
        roots,
        name,
        tags,
        compression_level,
        spool_dir,
    };
    // Serialize with GC; otherwise a dedupe hit can race chunk deletion.
    let lock = RepoLock::acquire(&client, &repo, "backup")?;
    let backup_result = run_backup(&client, &repo, &capability, &recipients, request);
    let unlock_result = lock.release();
    backup_result?;
    unlock_result?;
    Ok(())
}

struct BackupRequest {
    roots: Vec<PathBuf>,
    name: OsString,
    tags: Vec<OsString>,
    compression_level: i32,
    spool_dir: PathBuf,
}

fn run_backup(
    client: &S3Client,
    repo: &S3Repo,
    capability: &Capability,
    recipients: &[x25519::Recipient],
    request: BackupRequest,
) -> Result<()> {
    let created = unix_nanos()?;
    let parent_snapshot_id =
        latest_verified_commit(client, repo, capability.repo_id, &capability.commit_mac_key)?
            .map(|c| c.snapshot_id);
    let mut scan = ScanStats::default();
    let mut hardlinks: HashMap<(u64, u64), PathParts> = HashMap::new();
    let mut archive_roots = Vec::new();
    let mut used_root_names = HashSet::new();
    let mut chunk_refs = Vec::new();
    let (tx, rx) = sync_channel(2);
    let uploader = spawn_chunk_uploader(
        client.clone(),
        repo.clone(),
        recipients.to_vec(),
        capability.repo_id,
        request.compression_level,
        rx,
    );

    let scan_result = {
        let mut chunker = GearChunker::new(
            capability.gear_seed,
            capability.min_chunk,
            capability.target_chunk,
            capability.max_chunk,
            |chunk| {
                let chunk_id = chunk_id(&capability.chunk_id_key, &chunk);
                let plaintext_len = u32_checked(chunk.len(), "chunk length")?;
                chunk_refs.push(ChunkRef {
                    id: chunk_id,
                    plaintext_len,
                });
                tx.send(ChunkUploadJob {
                    id: chunk_id,
                    chunk,
                })
                .map_err(|e| format!("chunk uploader stopped: {e}"))?;
                Ok(())
            },
        )?;

        (|| -> Result<u64> {
            write_asar_header(&mut chunker, &capability.repo_id)?;
            for (idx, root) in request.roots.iter().enumerate() {
                let archive_root = archive_root_name(idx, root, &mut used_root_names);
                archive_roots.push(PathParts(vec![archive_root.clone()]));
                let mut backup_scan = BackupScan {
                    out: &mut chunker,
                    hardlinks: &mut hardlinks,
                    stats: &mut scan,
                    spool_dir: &request.spool_dir,
                };
                scan_path(root, PathParts(vec![archive_root]), &mut backup_scan)?;
            }
            chunker.write_all(&[REC_END])?;
            let archive_len = chunker.total_len;
            chunker.finish()?;
            Ok(archive_len)
        })()
    };
    drop(tx);
    let upload_result = uploader
        .join()
        .map_err(|_| "chunk uploader thread panicked".to_string())?;
    let archive_len = scan_result?;
    let unique_uploaded = upload_result?;

    let manifest = SnapshotManifest {
        repo_id: capability.repo_id,
        created_unix_ns: created,
        archive_len,
        name: request.name.into_vec(),
        tags: request
            .tags
            .into_iter()
            .map(OsStringExt::into_vec)
            .collect(),
        roots: archive_roots,
        files: scan.files,
        directories: scan.directories,
        symlinks: scan.symlinks,
        hardlinks: scan.hardlinks,
        logical_bytes: scan.logical_bytes,
        chunk_refs,
    };
    let manifest_plaintext = manifest.encode()?;
    let manifest_ciphertext = age_encrypt(recipients, &manifest_plaintext)?;
    let snapshot_id = *blake3::hash(&manifest_ciphertext).as_bytes();
    let manifest_key = manifest_key(&snapshot_id);
    put_immutable_new(client, repo, &manifest_key, manifest_ciphertext)?;

    let commit = Commit {
        repo_id: capability.repo_id,
        snapshot_id,
        manifest_key,
        created_unix_ns: created,
        parent_snapshot_id,
        mac: [0u8; 32],
    };
    let commit_text = commit.encode_signed(&capability.commit_mac_key);
    let commit_key = commit_key(created, &snapshot_id);
    put_immutable_new(client, repo, &commit_key, commit_text.into_bytes())?;

    println!("snapshot {}", hex(&snapshot_id));
    println!(
        "files={} dirs={} symlinks={} hardlinks={} skipped={} logical_bytes={} chunks={} uploaded={}",
        scan.files,
        scan.directories,
        scan.symlinks,
        scan.hardlinks,
        scan.skipped_files,
        scan.logical_bytes,
        manifest.chunk_refs.len(),
        unique_uploaded
    );
    if scan.skipped_files > 0 {
        return err_code(
            2,
            format!(
                "snapshot completed with {} skipped unstable file(s)",
                scan.skipped_files
            ),
        );
    }
    Ok(())
}

struct ChunkUploadJob {
    id: [u8; 32],
    chunk: Vec<u8>,
}

fn spawn_chunk_uploader(
    client: S3Client,
    repo: S3Repo,
    recipients: Vec<x25519::Recipient>,
    repo_id: [u8; 32],
    compression_level: i32,
    rx: Receiver<ChunkUploadJob>,
) -> thread::JoinHandle<Result<u64>> {
    thread::spawn(move || {
        let mut unique_uploaded = 0u64;
        while let Ok(job) = rx.recv() {
            let plaintext =
                encode_chunk_plaintext(&repo_id, &job.id, &job.chunk, compression_level)?;
            let ciphertext = age_encrypt(&recipients, &plaintext)?;
            if put_immutable(&client, &repo, &chunk_key(&job.id), ciphertext)? {
                unique_uploaded += 1;
            }
        }
        Ok(unique_uploaded)
    })
}

fn cmd_list(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let identity_path = p.value_path("--identity");
    p.finish()?;

    let client = s3_client(&repo, &s3_options)?;
    if let Some(identity_path) = identity_path {
        let identities = read_identities(&identity_path)?;
        let secrets = fetch_secrets(&client, &repo, &identities)?;
        let commits = verified_commits(&client, &repo, &secrets)?;
        for commit in commits {
            let manifest = fetch_verified_manifest(&client, &repo, &identities, &secrets, &commit)?;
            println!(
                "{} {} name={} tags={} roots={} files={} logical_bytes={} archive_bytes={}",
                manifest.created_unix_ns,
                hex(&commit.snapshot_id),
                display_bytes_lossy(&manifest.name),
                display_byte_list_lossy(&manifest.tags),
                display_roots_lossy(&manifest.roots),
                manifest.files,
                manifest.logical_bytes,
                manifest.archive_len
            );
        }
    } else {
        let commits = list_commits(&client, &repo)?;
        for commit in commits {
            println!(
                "{} {} {}",
                commit.created_unix_ns,
                hex(&commit.snapshot_id),
                commit.key
            );
        }
    }
    Ok(())
}

fn cmd_restore(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let mut metadata_policy = loaded_config
        .as_ref()
        .map_or(MetadataPolicy::Strict, |loaded| {
            loaded.config.metadata_policy
        });
    if let Some(value) = p.value("--metadata")? {
        metadata_policy = MetadataPolicy::parse(&value)?;
    }
    let identity_path = p.required_path("--identity")?;
    let snapshot = p.required_value("--snapshot")?;
    let target = p.required_path("--target")?;
    let restore_paths = p.values_os("--path");
    let overwrite = p.flag("--overwrite");
    p.finish()?;

    let client = s3_client(&repo, &s3_options)?;
    let identities = read_identities(&identity_path)?;
    let secrets = fetch_secrets(&client, &repo, &identities)?;
    let selected_restore = !restore_paths.is_empty();
    let filter = RestoreFilter::from_args(restore_paths)?;
    let mut extractor = AsarStreamExtractor::new(
        target.clone(),
        overwrite,
        filter,
        secrets.repo_id,
        metadata_policy,
    )?;
    stream_snapshot_archive(&client, &repo, &secrets, &identities, &snapshot, |chunk| {
        extractor.push(chunk)
    })?;
    extractor.finish()?;
    if selected_restore {
        println!("restored selected paths into {}", target.display());
    } else {
        println!("restored into {}", target.display());
    }
    Ok(())
}

fn cmd_check(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let identity_path = p.required_path("--identity")?;
    let snapshot = p.value("--snapshot")?.unwrap_or_else(|| "all".to_string());
    p.finish()?;

    let client = s3_client(&repo, &s3_options)?;
    let identities = read_identities(&identity_path)?;
    let secrets = fetch_secrets(&client, &repo, &identities)?;

    if snapshot == "all" {
        let commits = verified_commits(&client, &repo, &secrets)?;
        for commit in commits {
            let mut validator = AsarStreamValidator::new(secrets.repo_id);
            stream_snapshot_archive(
                &client,
                &repo,
                &secrets,
                &identities,
                &hex(&commit.snapshot_id),
                |chunk| validator.push(chunk),
            )?;
            validator.finish()?;
            println!("ok {}", hex(&commit.snapshot_id));
        }
    } else {
        let mut validator = AsarStreamValidator::new(secrets.repo_id);
        stream_snapshot_archive(&client, &repo, &secrets, &identities, &snapshot, |chunk| {
            validator.push(chunk)
        })?;
        validator.finish()?;
        println!("ok {snapshot}");
    }
    Ok(())
}

fn cmd_forget(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let keep_last: usize = p.required_value("--keep-last")?.parse()?;
    let identity_path = p.value_path("--identity");
    let capability_path = p.value_path("--capability").or_else(|| {
        loaded_config
            .as_ref()
            .and_then(LoadedLocalConfig::capability_path)
    });
    p.finish()?;

    let client = s3_client(&repo, &s3_options)?;
    let commits = if let Some(identity_path) = identity_path {
        let identities = read_identities(&identity_path)?;
        let secrets = fetch_secrets(&client, &repo, &identities)?;
        verified_commits(&client, &repo, &secrets)?
    } else if let Some(capability_path) = capability_path {
        let capability = Capability::parse(&read_to_string(&capability_path)?)?;
        if capability.repo != repo {
            return err("capability repo does not match --repo");
        }
        verified_commits_with_key(
            &client,
            &repo,
            capability.repo_id,
            &capability.commit_mac_key,
        )?
    } else {
        return err("forget requires --identity or --capability/config capability");
    };
    if commits.len() <= keep_last {
        println!("forgot 0 snapshot(s)");
        return Ok(());
    }

    let forget_count = commits.len() - keep_last;
    let lock = RepoLock::acquire(&client, &repo, "forget")?;
    let forget_result: Result<()> = (|| {
        for commit in commits.into_iter().take(forget_count) {
            s3_delete_existing(&client, &repo, &commit.key)?;
            s3_delete_any(&client, &repo, &commit.manifest_key)?;
            println!("forgot {}", hex(&commit.snapshot_id));
        }
        Ok(())
    })();
    let unlock_result = lock.release();
    forget_result?;
    unlock_result?;
    println!("forgot {forget_count} snapshot(s)");
    Ok(())
}

fn cmd_unlock(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let force = p.flag("--force");
    p.finish()?;

    if !force {
        return err("unlock requires --force");
    }
    let client = s3_client(&repo, &s3_options)?;
    s3_delete_any(&client, &repo, "locks/repo.lock")?;
    println!("removed locks/repo.lock");
    Ok(())
}

fn cmd_gc(args: Vec<OsString>) -> Result<()> {
    let mut p = ArgParser::new(args);
    let loaded_config = load_local_config_arg(&mut p)?;
    let repo = repo_from_args_or_config(&mut p, loaded_config.as_ref())?;
    let mut s3_options = loaded_config
        .as_ref()
        .map(|loaded| loaded.config.s3.clone())
        .unwrap_or_default();
    apply_s3_args(&mut p, &mut s3_options)?;
    let identity_path = p.required_path("--identity")?;
    let delete = p.flag("--delete");
    let min_age_secs = if let Some(value) = p.value("--min-age")? {
        parse_duration_secs(&value)?
    } else {
        loaded_config
            .as_ref()
            .map_or(DEFAULT_GC_MIN_AGE_SECS, |loaded| {
                loaded.config.gc_min_age_secs
            })
    };
    p.finish()?;

    let client = s3_client(&repo, &s3_options)?;
    let identities = read_identities(&identity_path)?;
    let secrets = fetch_secrets(&client, &repo, &identities)?;
    let lock = RepoLock::acquire(&client, &repo, "gc")?;
    let gc_result = run_gc(&client, &repo, &secrets, &identities, delete, min_age_secs);
    let unlock_result = lock.release();
    gc_result?;
    unlock_result?;
    Ok(())
}

fn run_gc(
    client: &S3Client,
    repo: &S3Repo,
    secrets: &RepoSecrets,
    identities: &[x25519::Identity],
    delete: bool,
    min_age_secs: u64,
) -> Result<()> {
    let commits = verified_commits(client, repo, secrets)?;
    let mut live_chunks: BTreeSet<String> = BTreeSet::new();
    let mut live_manifests: BTreeSet<String> = BTreeSet::new();

    for commit in commits {
        let ciphertext = s3_get(client, repo, &commit.manifest_key)?;
        let snapshot_id = *blake3::hash(&ciphertext).as_bytes();
        if snapshot_id != commit.snapshot_id {
            return err(format!("manifest hash mismatch for {}", commit.key));
        }
        let plaintext = age_decrypt(identities, &ciphertext)?;
        let manifest = SnapshotManifest::parse(&plaintext)?;
        if manifest.repo_id != secrets.repo_id {
            return err("manifest repo id mismatch during gc");
        }
        live_manifests.insert(commit.manifest_key);
        for chunk in manifest.chunk_refs {
            live_chunks.insert(chunk_key(&chunk.id));
        }
    }

    let all_chunks = list_objects(client, repo, "chunks/")?;
    let all_manifests = list_objects(client, repo, "manifests/")?;
    let now = unix_nanos()?;
    let min_age_ns = min_age_secs.saturating_mul(1_000_000_000);
    let mut removed = 0u64;
    let mut young = 0u64;
    for (object, live_set) in all_chunks
        .into_iter()
        .map(|object| (object, &live_chunks))
        .chain(
            all_manifests
                .into_iter()
                .map(|object| (object, &live_manifests)),
        )
    {
        let key = object.key;
        if !live_set.contains(&key) {
            let Some(last_modified_unix_ns) = object.last_modified_unix_ns else {
                eprintln!(
                    "agesnap: warning: skipping {key}: S3 listing did not include LastModified"
                );
                young += 1;
                continue;
            };
            if now.saturating_sub(last_modified_unix_ns) < min_age_ns {
                young += 1;
                continue;
            }
            if delete {
                s3_delete_existing(client, repo, &key)?;
                println!("deleted {key}");
            } else {
                println!("would delete {key}");
            }
            removed += 1;
        }
    }
    if !delete {
        println!("dry run: pass --delete to remove {removed} unreferenced objects");
    } else {
        println!("deleted {removed} unreferenced objects");
    }
    if young > 0 {
        println!(
            "kept {young} unreferenced object(s) younger than {}",
            format_duration_secs(min_age_secs)
        );
    }
    Ok(())
}

fn stream_snapshot_archive<F>(
    client: &S3Client,
    repo: &S3Repo,
    secrets: &RepoSecrets,
    identities: &[x25519::Identity],
    requested_snapshot: &str,
    mut consume: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let commits = verified_commits(client, repo, secrets)?;
    let commit = if requested_snapshot == "latest" {
        commits
            .into_iter()
            .last()
            .ok_or_else(|| "no committed snapshots".to_string())?
    } else {
        let wanted = parse_hex_32(requested_snapshot)?;
        commits
            .into_iter()
            .find(|c| c.snapshot_id == wanted)
            .ok_or_else(|| format!("snapshot not found: {requested_snapshot}"))?
    };

    let manifest_ciphertext = s3_get(client, repo, &commit.manifest_key)?;
    let snapshot_id = *blake3::hash(&manifest_ciphertext).as_bytes();
    if snapshot_id != commit.snapshot_id {
        return err("manifest ciphertext hash does not match commit snapshot id");
    }
    let manifest_plaintext = age_decrypt(identities, &manifest_ciphertext)?;
    let manifest = SnapshotManifest::parse(&manifest_plaintext)?;
    if manifest.repo_id != secrets.repo_id {
        return err("manifest repo id mismatch");
    }

    let mut archive_len = 0u64;
    for chunk_ref in &manifest.chunk_refs {
        let ciphertext = s3_get(client, repo, &chunk_key(&chunk_ref.id))?;
        let plaintext = age_decrypt(identities, &ciphertext)?;
        let chunk = decode_chunk_plaintext(
            &secrets.repo_id,
            &secrets.chunk_id_key,
            &chunk_ref.id,
            &plaintext,
        )?;
        if chunk.len() != chunk_ref.plaintext_len as usize {
            return err("chunk length mismatch against manifest");
        }
        archive_len = archive_len
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| "archive length overflow".to_string())?;
        consume(&chunk)?;
    }
    if archive_len != manifest.archive_len {
        return err("restored ASAR length does not match manifest");
    }
    Ok(())
}

struct BackupScan<'a> {
    out: &'a mut dyn Write,
    hardlinks: &'a mut HashMap<(u64, u64), PathParts>,
    stats: &'a mut ScanStats,
    spool_dir: &'a Path,
}

fn scan_path(source: &Path, archive_path: PathParts, scan: &mut BackupScan<'_>) -> Result<()> {
    let meta = fs::symlink_metadata(source)?;
    let md = Meta::from_metadata(&meta);
    let ft = meta.file_type();

    if ft.is_dir() {
        // Start from a pathname once, then switch to fd-relative traversal.
        let dir = open_backup_dir(source, &meta)?;
        scan_open_dir(source, archive_path, md, dir, scan)?;
    } else if ft.is_symlink() {
        let target = fs::read_link(source)?;
        write_symlink_record(scan.out, &archive_path, md, target.as_os_str().as_bytes())?;
        scan.stats.symlinks += 1;
    } else if ft.is_file() {
        let key = (meta.dev(), meta.ino());
        if meta.nlink() > 1
            && let Some(first) = scan.hardlinks.get(&key)
        {
            write_hardlink_record(scan.out, &archive_path, first, md)?;
            scan.stats.hardlinks += 1;
            return Ok(());
        }

        if let Some(identity) =
            write_stable_file_record(source, &archive_path, scan.out, scan.stats, scan.spool_dir)?
            && identity.nlink > 1
        {
            scan.hardlinks
                .insert((identity.dev, identity.ino), archive_path.clone());
        }
    } else {
        return err(format!("unsupported file type: {}", source.display()));
    }

    Ok(())
}

fn scan_path_at(
    parent_fd: libc::c_int,
    name: &CString,
    display_path: &Path,
    archive_path: PathParts,
    scan: &mut BackupScan<'_>,
) -> Result<()> {
    // `display_path` is only for diagnostics; the parent fd decides what opens.
    let st = fstatat_optional(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW)?
        .ok_or_else(|| format!("path disappeared before backup: {}", display_path.display()))?;
    let md = meta_from_stat(&st);

    if stat_is_dir(&st) {
        let dir = open_dir_at(parent_fd, name)?;
        if !same_dir_stat(&dir.metadata()?, &st) {
            return err(format!(
                "directory changed while opening for backup: {}",
                display_path.display()
            ));
        }
        scan_open_dir(display_path, archive_path, md, dir, scan)?;
    } else if stat_is_symlink(&st) {
        let target = readlinkat_name(parent_fd, name)?;
        write_symlink_record(scan.out, &archive_path, md, &target)?;
        scan.stats.symlinks += 1;
    } else if stat_is_file(&st) {
        let key = (st.st_dev as u64, st.st_ino as u64);
        if st.st_nlink > 1
            && let Some(first) = scan.hardlinks.get(&key)
        {
            write_hardlink_record(scan.out, &archive_path, first, md)?;
            scan.stats.hardlinks += 1;
            return Ok(());
        }

        if let Some(identity) =
            write_stable_file_record_at(parent_fd, name, display_path, &archive_path, scan)?
            && identity.nlink > 1
        {
            scan.hardlinks
                .insert((identity.dev, identity.ino), archive_path.clone());
        }
    } else {
        return err(format!("unsupported file type: {}", display_path.display()));
    }

    Ok(())
}

fn scan_open_dir(
    display_path: &Path,
    archive_path: PathParts,
    meta: Meta,
    dir: File,
    scan: &mut BackupScan<'_>,
) -> Result<()> {
    write_dir_record(scan.out, &archive_path, meta)?;
    scan.stats.directories += 1;

    // Sort names for deterministic archives; re-stat each name before use.
    for name in read_dir_names_fd(&dir)? {
        validate_component(&name)?;
        let c_name = c_component(&name)?;
        let mut child_archive = archive_path.clone();
        child_archive.0.push(name.clone());
        let child_display = display_path.join(Path::new(OsStr::from_bytes(&name)));
        scan_path_at(
            dir.as_raw_fd(),
            &c_name,
            &child_display,
            child_archive,
            scan,
        )?;
    }
    Ok(())
}

fn open_backup_dir(source: &Path, expected: &fs::Metadata) -> Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    if !same_dir_metadata(&dir.metadata()?, expected) {
        return err(format!(
            "directory changed while opening for backup: {}",
            source.display()
        ));
    }
    Ok(dir)
}

fn read_dir_names_fd(dir: &File) -> Result<Vec<Vec<u8>>> {
    // `fdopendir` closes its fd, so duplicate the caller's directory fd first.
    let fd = dir.try_clone()?.into_raw_fd();
    // SAFETY: `fd` is a valid duplicated directory fd. `fdopendir` takes
    // ownership on success; on failure we close it below.
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so ownership of `fd` was not transferred.
        unsafe {
            libc::close(fd);
        }
        return Err(error.into());
    }
    let stream = DirStream(raw);
    let mut names = Vec::new();
    loop {
        set_errno(0);
        // SAFETY: `stream.0` is a valid `DIR*` owned by `stream`.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = errno();
            if errno == 0 {
                break;
            }
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        // SAFETY: `readdir` returned a valid entry whose `d_name` is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(name.to_vec());
    }
    names.sort();
    Ok(names)
}

struct DirStream(*mut libc::DIR);

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: `DirStream` owns this `DIR*` and closes it exactly once.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn set_errno(value: libc::c_int) {
    // SAFETY: `__errno_location` returns a valid pointer to thread-local errno on Linux.
    unsafe {
        *libc::__errno_location() = value;
    }
}

fn errno() -> libc::c_int {
    // SAFETY: `__errno_location` returns a valid pointer to thread-local errno on Linux.
    unsafe { *libc::__errno_location() }
}

fn write_stable_file_record(
    source: &Path,
    archive_path: &PathParts,
    out: &mut dyn Write,
    stats: &mut ScanStats,
    spool_dir: &Path,
) -> Result<Option<FileIdentity>> {
    let mut last_error = String::new();
    for attempt in 0..2 {
        match spool_file_record(source, archive_path, spool_dir) {
            Ok((spool, len, identity)) => {
                spool.copy_into(out)?;
                stats.files += 1;
                stats.logical_bytes = stats.logical_bytes.saturating_add(len);
                return Ok(Some(identity));
            }
            Err(e) if is_unstable_file_error(e.as_ref()) => {
                last_error = e.to_string();
                if attempt == 0 {
                    continue;
                }
            }
            Err(e) => return Err(e),
        }
    }
    stats.skipped_files += 1;
    eprintln!(
        "agesnap: warning: skipped unstable file after retry: {} ({last_error})",
        source.display()
    );
    Ok(None)
}

fn write_stable_file_record_at(
    parent_fd: libc::c_int,
    name: &CString,
    display_path: &Path,
    archive_path: &PathParts,
    scan: &mut BackupScan<'_>,
) -> Result<Option<FileIdentity>> {
    let mut last_error = String::new();
    for attempt in 0..2 {
        match spool_file_record_at(parent_fd, name, display_path, archive_path, scan.spool_dir) {
            Ok((spool, len, identity)) => {
                spool.copy_into(scan.out)?;
                scan.stats.files += 1;
                scan.stats.logical_bytes = scan.stats.logical_bytes.saturating_add(len);
                return Ok(Some(identity));
            }
            Err(e) if is_unstable_file_error(e.as_ref()) => {
                last_error = e.to_string();
                if attempt == 0 {
                    continue;
                }
            }
            Err(e) => return Err(e),
        }
    }
    scan.stats.skipped_files += 1;
    eprintln!(
        "agesnap: warning: skipped unstable file after retry: {} ({last_error})",
        display_path.display()
    );
    Ok(None)
}

#[derive(Clone, Copy)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    nlink: u64,
}

fn spool_file_record(
    source: &Path,
    archive_path: &PathParts,
    spool_dir: &Path,
) -> Result<(TempSpoolFile, u64, FileIdentity)> {
    let expected = match fs::symlink_metadata(source) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return err_unstable_file(format!(
                "file disappeared before backup: {}",
                source.display()
            ));
        }
        Err(e) => return Err(e.into()),
    };
    if !expected.file_type().is_file() {
        return err_unstable_file(format!(
            "file type changed before backup: {}",
            source.display()
        ));
    }
    let md = Meta::from_metadata(&expected);
    let mut spool = TempSpoolFile::create(spool_dir)?;
    write_file_header(&mut spool.file, archive_path, md, expected.len())?;
    let mut file = open_backup_file(source, &expected)?;
    copy_backup_file(source, &mut file, &expected, &mut spool.file)?;
    Ok((
        spool,
        expected.len(),
        FileIdentity {
            dev: expected.dev(),
            ino: expected.ino(),
            nlink: expected.nlink(),
        },
    ))
}

fn spool_file_record_at(
    parent_fd: libc::c_int,
    name: &CString,
    display_path: &Path,
    archive_path: &PathParts,
    spool_dir: &Path,
) -> Result<(TempSpoolFile, u64, FileIdentity)> {
    let expected = match fstatat_optional(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW)? {
        Some(st) => st,
        None => {
            return err_unstable_file(format!(
                "file disappeared before backup: {}",
                display_path.display()
            ));
        }
    };
    if !stat_is_file(&expected) {
        return err_unstable_file(format!(
            "file type changed before backup: {}",
            display_path.display()
        ));
    }
    let len = stat_size_u64(&expected, display_path)?;
    let md = meta_from_stat(&expected);
    let mut spool = TempSpoolFile::create(spool_dir)?;
    write_file_header(&mut spool.file, archive_path, md, len)?;
    let mut file = open_backup_file_at(parent_fd, name, display_path, &expected)?;
    copy_backup_file_at(display_path, &mut file, &expected, &mut spool.file)?;
    Ok((
        spool,
        len,
        FileIdentity {
            dev: expected.st_dev as u64,
            ino: expected.st_ino as u64,
            nlink: expected.st_nlink as u64,
        },
    ))
}

fn open_backup_file(source: &Path, expected: &fs::Metadata) -> Result<File> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return err_unstable_file(format!(
                "file disappeared while opening for backup: {}",
                source.display()
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let opened = file.metadata()?;
    if !same_file_snapshot(&opened, expected) {
        return err_unstable_file(format!(
            "file changed while opening for backup: {}",
            source.display()
        ));
    }
    Ok(file)
}

fn open_backup_file_at(
    parent_fd: libc::c_int,
    name: &CString,
    display_path: &Path,
    expected: &libc::stat,
) -> Result<File> {
    let file = match open_file_read_at(parent_fd, name) {
        Ok(file) => file,
        Err(e)
            if raw_os_error_is(&e, libc::ENOENT)
                || raw_os_error_is(&e, libc::ELOOP)
                || raw_os_error_is(&e, libc::EISDIR) =>
        {
            return err_unstable_file(format!(
                "file changed while opening for backup: {}",
                display_path.display()
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let opened = file.metadata()?;
    if !same_file_stat(&opened, expected) {
        return err_unstable_file(format!(
            "file changed while opening for backup: {}",
            display_path.display()
        ));
    }
    Ok(file)
}

fn copy_backup_file(
    source: &Path,
    file: &mut File,
    expected: &fs::Metadata,
    out: &mut dyn Write,
) -> Result<()> {
    let copied = {
        let mut input = (&mut *file).take(expected.len());
        std::io::copy(&mut input, out)?
    };
    if copied != expected.len() {
        return err_unstable_file(format!(
            "file became shorter during backup: {}",
            source.display()
        ));
    }

    let after = file.metadata()?;
    if !same_file_snapshot(&after, expected) {
        return err_unstable_file(format!(
            "file changed while being backed up: {}",
            source.display()
        ));
    }
    Ok(())
}

fn copy_backup_file_at(
    display_path: &Path,
    file: &mut File,
    expected: &libc::stat,
    out: &mut dyn Write,
) -> Result<()> {
    let len = stat_size_u64(expected, display_path)?;
    let copied = {
        let mut input = (&mut *file).take(len);
        std::io::copy(&mut input, out)?
    };
    if copied != len {
        return err_unstable_file(format!(
            "file became shorter during backup: {}",
            display_path.display()
        ));
    }

    let after = file.metadata()?;
    if !same_file_stat(&after, expected) {
        return err_unstable_file(format!(
            "file changed while being backed up: {}",
            display_path.display()
        ));
    }
    Ok(())
}

fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn same_file_stat(left: &fs::Metadata, right: &libc::stat) -> bool {
    left.file_type().is_file()
        && left.dev() == right.st_dev
        && left.ino() == right.st_ino
        && left.len() == right.st_size as u64
        && left.mtime() == right.st_mtime
        && left.mtime_nsec() == right.st_mtime_nsec
        && left.ctime() == right.st_ctime
        && left.ctime_nsec() == right.st_ctime_nsec
}

fn same_dir_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type().is_dir() && left.dev() == right.dev() && left.ino() == right.ino()
}

fn same_dir_stat(left: &fs::Metadata, right: &libc::stat) -> bool {
    left.file_type().is_dir() && left.dev() == right.st_dev && left.ino() == right.st_ino
}

fn stat_size_u64(st: &libc::stat, path: &Path) -> Result<u64> {
    if st.st_size < 0 {
        return err_unstable_file(format!("file has negative size: {}", path.display()));
    }
    Ok(st.st_size as u64)
}

#[derive(Debug)]
struct UnstableFileError {
    message: String,
}

impl std::fmt::Display for UnstableFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnstableFileError {}

fn err_unstable_file<T>(message: impl Into<String>) -> Result<T> {
    Err(Box::new(UnstableFileError {
        message: message.into(),
    }))
}

fn is_unstable_file_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error.is::<UnstableFileError>()
}

struct TempSpoolFile {
    path: PathBuf,
    file: File,
}

impl TempSpoolFile {
    fn create(dir: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return err(format!(
                "spool directory is not a real directory: {}",
                dir.display()
            ));
        }
        for _ in 0..100 {
            let mut random = [0u8; 16];
            fill_random(&mut random)?;
            let path = dir.join(format!("agesnap-spool-{}", hex(&random)));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        err("could not allocate backup spool file")
    }

    fn copy_into(mut self, out: &mut dyn Write) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut self.file, out)?;
        Ok(())
    }
}

impl Drop for TempSpoolFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_asar_header(out: &mut dyn Write, repo_id: &[u8; 32]) -> Result<()> {
    out.write_all(ASAR_MAGIC)?;
    write_u16(out, 1)?;
    write_u16(out, 0)?;
    out.write_all(repo_id)?;
    Ok(())
}

fn write_dir_record(out: &mut dyn Write, path: &PathParts, meta: Meta) -> Result<()> {
    out.write_all(&[REC_DIR])?;
    write_path(out, path)?;
    write_meta(out, meta)?;
    Ok(())
}

fn write_file_header(out: &mut dyn Write, path: &PathParts, meta: Meta, size: u64) -> Result<()> {
    out.write_all(&[REC_FILE])?;
    write_path(out, path)?;
    write_meta(out, meta)?;
    write_u64(out, size)?;
    Ok(())
}

fn write_symlink_record(
    out: &mut dyn Write,
    path: &PathParts,
    meta: Meta,
    target: &[u8],
) -> Result<()> {
    if target.len() > MAX_SYMLINK_TARGET_BYTES {
        return err("symlink target exceeds 1 MiB");
    }
    out.write_all(&[REC_SYMLINK])?;
    write_path(out, path)?;
    write_meta(out, meta)?;
    write_bytes(out, target)?;
    Ok(())
}

fn write_hardlink_record(
    out: &mut dyn Write,
    path: &PathParts,
    target: &PathParts,
    meta: Meta,
) -> Result<()> {
    out.write_all(&[REC_HARDLINK])?;
    write_path(out, path)?;
    write_path(out, target)?;
    write_meta(out, meta)?;
    Ok(())
}

struct AsarStreamExtractor {
    target: RestoreRoot,
    overwrite: bool,
    filter: RestoreFilter,
    expected_repo_id: [u8; 32],
    metadata_policy: MetadataPolicy,
    matched_paths: Vec<bool>,
    restored_paths: HashSet<PathParts>,
    buf: Vec<u8>,
    header_done: bool,
    done: bool,
    current_file: Option<ActiveFile>,
    dirs_to_finalize: Vec<(PathParts, Meta)>,
}

impl AsarStreamExtractor {
    fn new(
        target: PathBuf,
        overwrite: bool,
        filter: RestoreFilter,
        expected_repo_id: [u8; 32],
        metadata_policy: MetadataPolicy,
    ) -> Result<Self> {
        let target = RestoreRoot::prepare(target)?;
        let matched_paths = vec![false; filter.selections.len()];
        Ok(Self {
            target,
            overwrite,
            filter,
            expected_repo_id,
            metadata_policy,
            matched_paths,
            restored_paths: HashSet::new(),
            buf: Vec::new(),
            header_done: false,
            done: false,
            current_file: None,
            dirs_to_finalize: Vec::new(),
        })
    }

    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.done && !bytes.is_empty() {
            return err("trailing bytes after ASAR end record");
        }
        self.buf.extend_from_slice(bytes);
        self.process()
    }

    fn finish(mut self) -> Result<()> {
        self.process()?;
        if self.current_file.is_some() {
            return err("truncated ASAR file payload");
        }
        if !self.done {
            return err("missing ASAR end record");
        }
        if !self.buf.is_empty() {
            return err("trailing bytes after ASAR end record");
        }
        for (path, meta) in self.dirs_to_finalize.into_iter().rev() {
            let dir = self.target.open_dir(&path)?;
            apply_file_dir_metadata_fd(dir.as_raw_fd(), meta, self.metadata_policy)?;
        }
        if let Some(path) = self.filter.first_missing(&self.matched_paths) {
            return err(format!("restore path not found: {}", path.display_lossy()));
        }
        Ok(())
    }

    fn process(&mut self) -> Result<()> {
        loop {
            if !self.header_done {
                let header_len = ASAR_MAGIC.len() + 2 + 2 + 32;
                if self.buf.len() < header_len {
                    return Ok(());
                }
                let mut r = Reader::new(&self.buf[..header_len]);
                r.expect_bytes(ASAR_MAGIC)?;
                let version = r.u16()?;
                let flags = r.u16()?;
                if version != 1 || flags != 0 {
                    return err("unsupported ASAR header");
                }
                let repo_id = r.array_32()?;
                if repo_id != self.expected_repo_id {
                    return err("ASAR repo id mismatch");
                }
                r.finish()?;
                self.buf.drain(..header_len);
                self.header_done = true;
                continue;
            }

            if let Some(active_file) = self.current_file.as_mut() {
                if active_file.remaining() == 0 {
                    let active_file = self.current_file.take().expect("checked current file");
                    if let ActiveFile::Restore(file) = active_file {
                        let path = finish_file_restore(file)?;
                        self.restored_paths.insert(path);
                    }
                    continue;
                }
                if self.buf.is_empty() {
                    return Ok(());
                }
                let n = self
                    .buf
                    .len()
                    .min(usize_checked_u64(active_file.remaining(), "file payload")?);
                if let ActiveFile::Restore(file) = active_file {
                    file.file.write_all(&self.buf[..n])?;
                }
                active_file.consume(n as u64);
                self.buf.drain(..n);
                continue;
            }

            if self.done {
                if self.buf.is_empty() {
                    return Ok(());
                }
                return err("trailing bytes after ASAR end record");
            }

            let Some((record, consumed)) = try_parse_record(&self.buf)? else {
                return Ok(());
            };
            self.buf.drain(..consumed);
            match record {
                ParsedRecord::Directory(path, meta) => {
                    if self.filter.should_restore(&path) {
                        self.filter.mark_matched(&path, &mut self.matched_paths);
                        restore_dir(&self.target, &path, self.overwrite)?;
                        self.restored_paths.insert(path.clone());
                        self.dirs_to_finalize.push((path, meta));
                    }
                }
                ParsedRecord::File(path, meta, size) => {
                    if self.filter.should_restore(&path) {
                        self.filter.mark_matched(&path, &mut self.matched_paths);
                        self.current_file = Some(ActiveFile::Restore(start_file_restore(
                            &self.target,
                            path,
                            meta,
                            size,
                            self.overwrite,
                            self.metadata_policy,
                        )?));
                    } else {
                        self.current_file = Some(ActiveFile::Skip { remaining: size });
                    }
                }
                ParsedRecord::Symlink(path, meta, target) => {
                    if self.filter.should_restore(&path) {
                        self.filter.mark_matched(&path, &mut self.matched_paths);
                        restore_symlink(
                            &self.target,
                            &path,
                            &target,
                            meta,
                            self.overwrite,
                            self.metadata_policy,
                        )?;
                        self.restored_paths.insert(path);
                    }
                }
                ParsedRecord::Hardlink(path, target, meta) => {
                    if self.filter.should_restore(&path) {
                        self.filter.mark_matched(&path, &mut self.matched_paths);
                        if !self.restored_paths.contains(&target) {
                            return err(format!(
                                "selected hardlink target was not restored: {}",
                                target.display_lossy()
                            ));
                        }
                        if restore_hardlink(
                            &self.target,
                            &path,
                            &target,
                            meta,
                            self.overwrite,
                            self.metadata_policy,
                        )? {
                            self.restored_paths.insert(path);
                        }
                    }
                }
                ParsedRecord::End => {
                    self.done = true;
                }
            }
        }
    }
}

struct AsarStreamValidator {
    expected_repo_id: [u8; 32],
    buf: Vec<u8>,
    header_done: bool,
    done: bool,
    current_file_remaining: Option<u64>,
    seen_paths: HashSet<PathParts>,
}

impl AsarStreamValidator {
    fn new(expected_repo_id: [u8; 32]) -> Self {
        Self {
            expected_repo_id,
            buf: Vec::new(),
            header_done: false,
            done: false,
            current_file_remaining: None,
            seen_paths: HashSet::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.done && !bytes.is_empty() {
            return err("trailing bytes after ASAR end record");
        }
        self.buf.extend_from_slice(bytes);
        self.process()
    }

    fn finish(mut self) -> Result<()> {
        self.process()?;
        if self.current_file_remaining.is_some() {
            return err("truncated ASAR file payload");
        }
        if !self.done {
            return err("missing ASAR end record");
        }
        if !self.buf.is_empty() {
            return err("trailing bytes after ASAR end record");
        }
        Ok(())
    }

    fn process(&mut self) -> Result<()> {
        loop {
            if !self.header_done {
                let header_len = ASAR_MAGIC.len() + 2 + 2 + 32;
                if self.buf.len() < header_len {
                    return Ok(());
                }
                let mut r = Reader::new(&self.buf[..header_len]);
                r.expect_bytes(ASAR_MAGIC)?;
                let version = r.u16()?;
                let flags = r.u16()?;
                if version != 1 || flags != 0 {
                    return err("unsupported ASAR header");
                }
                let repo_id = r.array_32()?;
                if repo_id != self.expected_repo_id {
                    return err("ASAR repo id mismatch");
                }
                r.finish()?;
                self.buf.drain(..header_len);
                self.header_done = true;
                continue;
            }

            if let Some(remaining) = self.current_file_remaining.as_mut() {
                if *remaining == 0 {
                    self.current_file_remaining = None;
                    continue;
                }
                if self.buf.is_empty() {
                    return Ok(());
                }
                let n = self
                    .buf
                    .len()
                    .min(usize_checked_u64(*remaining, "file payload")?);
                *remaining -= n as u64;
                self.buf.drain(..n);
                continue;
            }

            if self.done {
                if self.buf.is_empty() {
                    return Ok(());
                }
                return err("trailing bytes after ASAR end record");
            }

            let Some((record, consumed)) = try_parse_record(&self.buf)? else {
                return Ok(());
            };
            self.buf.drain(..consumed);
            match record {
                ParsedRecord::Directory(path, _) | ParsedRecord::Symlink(path, _, _) => {
                    self.remember_path(path)?;
                }
                ParsedRecord::File(path, _, size) => {
                    self.remember_path(path)?;
                    self.current_file_remaining = Some(size);
                }
                ParsedRecord::Hardlink(path, target, _) => {
                    if !self.seen_paths.contains(&target) {
                        return err(format!(
                            "hardlink target appears after link: {}",
                            target.display_lossy()
                        ));
                    }
                    self.remember_path(path)?;
                }
                ParsedRecord::End => {
                    self.done = true;
                }
            }
        }
    }

    fn remember_path(&mut self, path: PathParts) -> Result<()> {
        if !self.seen_paths.insert(path.clone()) {
            return err(format!("duplicate ASAR path: {}", path.display_lossy()));
        }
        Ok(())
    }
}

struct RestoreFilter {
    selections: Vec<PathParts>,
}

impl RestoreFilter {
    fn from_args(paths: Vec<OsString>) -> Result<Self> {
        let mut selections = Vec::with_capacity(paths.len());
        for path in paths {
            selections.push(parse_restore_path_arg(&path)?);
        }
        Ok(Self { selections })
    }

    fn should_restore(&self, path: &PathParts) -> bool {
        self.selections.is_empty()
            || self
                .selections
                .iter()
                .any(|selected| selected.is_prefix_of(path))
    }

    fn mark_matched(&self, path: &PathParts, matched: &mut [bool]) {
        for (idx, selected) in self.selections.iter().enumerate() {
            if selected.is_prefix_of(path) {
                matched[idx] = true;
            }
        }
    }

    fn first_missing<'a>(&'a self, matched: &[bool]) -> Option<&'a PathParts> {
        self.selections
            .iter()
            .zip(matched)
            .find_map(|(path, matched)| if *matched { None } else { Some(path) })
    }
}

enum ActiveFile {
    Restore(FileRestore),
    Skip { remaining: u64 },
}

impl ActiveFile {
    fn remaining(&self) -> u64 {
        match self {
            ActiveFile::Restore(file) => file.remaining,
            ActiveFile::Skip { remaining } => *remaining,
        }
    }

    fn consume(&mut self, n: u64) {
        match self {
            ActiveFile::Restore(file) => file.remaining -= n,
            ActiveFile::Skip { remaining } => *remaining -= n,
        }
    }
}

struct FileRestore {
    path: PathParts,
    parent: File,
    name: CString,
    temp_name: CString,
    file: File,
    remaining: u64,
    meta: Meta,
    overwrite: bool,
    metadata_policy: MetadataPolicy,
}

enum ParsedRecord {
    Directory(PathParts, Meta),
    File(PathParts, Meta, u64),
    Symlink(PathParts, Meta, Vec<u8>),
    Hardlink(PathParts, PathParts, Meta),
    End,
}

fn try_parse_record(buf: &[u8]) -> Result<Option<(ParsedRecord, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let mut pos = 1usize;
    let record = match buf[0] {
        REC_DIR => {
            let Some(path) = try_read_path(buf, &mut pos)? else {
                return Ok(None);
            };
            let Some(meta) = try_read_meta(buf, &mut pos) else {
                return Ok(None);
            };
            ParsedRecord::Directory(path, meta)
        }
        REC_FILE => {
            let Some(path) = try_read_path(buf, &mut pos)? else {
                return Ok(None);
            };
            let Some(meta) = try_read_meta(buf, &mut pos) else {
                return Ok(None);
            };
            let Some(size) = try_read_u64(buf, &mut pos) else {
                return Ok(None);
            };
            ParsedRecord::File(path, meta, size)
        }
        REC_SYMLINK => {
            let Some(path) = try_read_path(buf, &mut pos)? else {
                return Ok(None);
            };
            let Some(meta) = try_read_meta(buf, &mut pos) else {
                return Ok(None);
            };
            let Some(target) =
                try_read_bytes(buf, &mut pos, MAX_SYMLINK_TARGET_BYTES, "symlink target")?
            else {
                return Ok(None);
            };
            ParsedRecord::Symlink(path, meta, target)
        }
        REC_HARDLINK => {
            let Some(path) = try_read_path(buf, &mut pos)? else {
                return Ok(None);
            };
            let Some(target) = try_read_path(buf, &mut pos)? else {
                return Ok(None);
            };
            let Some(meta) = try_read_meta(buf, &mut pos) else {
                return Ok(None);
            };
            ParsedRecord::Hardlink(path, target, meta)
        }
        REC_END => ParsedRecord::End,
        _ => return err("unknown ASAR record type"),
    };
    Ok(Some((record, pos)))
}

fn try_read_path(buf: &[u8], pos: &mut usize) -> Result<Option<PathParts>> {
    let Some(count) = try_read_u16(buf, pos) else {
        return Ok(None);
    };
    if count == 0 {
        return err("path has no components");
    }
    if usize::from(count) > MAX_PATH_COMPONENTS {
        return err("path has too many components");
    }
    let mut components = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(len) = try_read_u16(buf, pos) else {
            return Ok(None);
        };
        let len = len as usize;
        let Some(bytes) = try_take(buf, pos, len) else {
            return Ok(None);
        };
        validate_component(bytes)?;
        components.push(bytes.to_vec());
    }
    Ok(Some(PathParts(components)))
}

fn try_read_meta(buf: &[u8], pos: &mut usize) -> Option<Meta> {
    Some(Meta {
        mode: try_read_u32(buf, pos)?,
        uid: try_read_u32(buf, pos)?,
        gid: try_read_u32(buf, pos)?,
        mtime_ns: try_read_u64(buf, pos)?,
    })
}

fn try_read_bytes(
    buf: &[u8],
    pos: &mut usize,
    max_len: usize,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(len) = try_read_u32(buf, pos) else {
        return Ok(None);
    };
    let len = len as usize;
    if len > max_len {
        return err(format!("{label} exceeds maximum length"));
    }
    Ok(Some(match try_take(buf, pos, len) {
        Some(bytes) => bytes.to_vec(),
        None => return Ok(None),
    }))
}

fn try_read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let bytes = try_take(buf, pos, 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn try_read_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let bytes = try_take(buf, pos, 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn try_read_u64(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let bytes = try_take(buf, pos, 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn try_take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(n)?;
    if end > buf.len() {
        return None;
    }
    let bytes = &buf[*pos..end];
    *pos = end;
    Some(bytes)
}

struct RestoreRoot {
    dir: File,
}

impl RestoreRoot {
    fn prepare(target: PathBuf) -> Result<Self> {
        if target.exists() {
            let meta = fs::symlink_metadata(&target)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return err("restore target must be a real directory");
            }
        } else {
            fs::create_dir_all(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        }

        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&target)?;
        Ok(Self { dir })
    }

    fn parent_dir(&self, path: &PathParts) -> Result<(File, CString)> {
        path.validate()?;
        let mut dir = self.dir.try_clone()?;
        for component in &path.0[..path.0.len() - 1] {
            let name = c_component(component)?;
            dir = open_or_create_dir_at(dir.as_raw_fd(), &name)?;
        }
        let name = c_component(path.0.last().expect("validated path has a component"))?;
        Ok((dir, name))
    }

    fn existing_parent_dir(&self, path: &PathParts) -> Result<(File, CString)> {
        path.validate()?;
        let mut dir = self.dir.try_clone()?;
        for component in &path.0[..path.0.len() - 1] {
            let name = c_component(component)?;
            dir = open_dir_at(dir.as_raw_fd(), &name)?;
        }
        let name = c_component(path.0.last().expect("validated path has a component"))?;
        Ok((dir, name))
    }

    fn open_dir(&self, path: &PathParts) -> Result<File> {
        let (parent, name) = self.existing_parent_dir(path)?;
        open_dir_at(parent.as_raw_fd(), &name)
    }
}

fn restore_dir(root: &RestoreRoot, path: &PathParts, overwrite: bool) -> Result<()> {
    let (parent, name) = root.parent_dir(path)?;
    match fstatat_optional(parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW)? {
        Some(st) => {
            if !stat_is_dir(&st) {
                if overwrite {
                    return err("cannot overwrite non-directory with directory");
                }
                return err("restore target exists");
            }
            if !overwrite {
                return err("restore target exists");
            }
            let dir = open_dir_at(parent.as_raw_fd(), &name)?;
            fchmod_fd(dir.as_raw_fd(), 0o700)?;
        }
        None => match mkdirat_name(parent.as_raw_fd(), &name, 0o700) {
            Ok(()) => {
                let dir = open_dir_at(parent.as_raw_fd(), &name)?;
                fchmod_fd(dir.as_raw_fd(), 0o700)?;
            }
            Err(e) if raw_os_error_is(&e, libc::EEXIST) && overwrite => {
                let dir = open_dir_at(parent.as_raw_fd(), &name)?;
                fchmod_fd(dir.as_raw_fd(), 0o700)?;
            }
            Err(e) if raw_os_error_is(&e, libc::EEXIST) => return err("restore target exists"),
            Err(e) => return Err(e.into()),
        },
    }
    Ok(())
}

fn start_file_restore(
    root: &RestoreRoot,
    path: PathParts,
    meta: Meta,
    size: u64,
    overwrite: bool,
    metadata_policy: MetadataPolicy,
) -> Result<FileRestore> {
    let (parent, name) = root.parent_dir(&path)?;
    check_file_restore_target_at(parent.as_raw_fd(), &name, overwrite)?;
    let (temp_name, file) = create_temp_file_at(parent.as_raw_fd(), &name)?;
    Ok(FileRestore {
        path,
        parent,
        name,
        temp_name,
        file,
        remaining: size,
        meta,
        overwrite,
        metadata_policy,
    })
}

fn finish_file_restore(restore: FileRestore) -> Result<PathParts> {
    // Metadata is applied to the temp file before final placement.
    let mut temp_cleanup = RestoreTempCleanup::new(restore.parent.as_raw_fd(), &restore.temp_name);
    apply_file_dir_metadata_fd(
        restore.file.as_raw_fd(),
        restore.meta,
        restore.metadata_policy,
    )?;
    restore.file.sync_all()?;
    if restore.overwrite {
        renameat_name(
            restore.parent.as_raw_fd(),
            &restore.temp_name,
            restore.parent.as_raw_fd(),
            &restore.name,
        )?;
    } else {
        linkat_name(
            restore.parent.as_raw_fd(),
            &restore.temp_name,
            restore.parent.as_raw_fd(),
            &restore.name,
        )?;
        unlinkat_name(restore.parent.as_raw_fd(), &restore.temp_name)?;
    }
    temp_cleanup.disarm();
    drop(temp_cleanup);
    let path = restore.path;
    drop(restore.file);
    Ok(path)
}

struct RestoreTempCleanup<'a> {
    parent_fd: libc::c_int,
    temp_name: &'a CString,
    armed: bool,
}

impl<'a> RestoreTempCleanup<'a> {
    fn new(parent_fd: libc::c_int, temp_name: &'a CString) -> Self {
        Self {
            parent_fd,
            temp_name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RestoreTempCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Keep the original restore error; temp cleanup is best effort.
            let _ = unlinkat_name(self.parent_fd, self.temp_name);
        }
    }
}

fn restore_symlink(
    root: &RestoreRoot,
    path: &PathParts,
    target: &[u8],
    meta: Meta,
    overwrite: bool,
    metadata_policy: MetadataPolicy,
) -> Result<()> {
    if target.contains(&0) {
        return err("symlink target contains NUL");
    }
    let (parent, name) = root.parent_dir(path)?;
    check_replace_target_at(parent.as_raw_fd(), &name, overwrite)?;
    let target = CString::new(target)?;
    if overwrite {
        let temp_name = create_temp_symlink_at(parent.as_raw_fd(), &target)?;
        let mut temp_cleanup = RestoreTempCleanup::new(parent.as_raw_fd(), &temp_name);
        apply_symlink_metadata_at(parent.as_raw_fd(), &temp_name, meta, metadata_policy)?;
        renameat_name(parent.as_raw_fd(), &temp_name, parent.as_raw_fd(), &name)?;
        temp_cleanup.disarm();
    } else {
        symlinkat_name(&target, parent.as_raw_fd(), &name)?;
        apply_symlink_metadata_at(parent.as_raw_fd(), &name, meta, metadata_policy)?;
    }
    Ok(())
}

fn restore_hardlink(
    root: &RestoreRoot,
    path: &PathParts,
    target_path: &PathParts,
    _meta: Meta,
    overwrite: bool,
    metadata_policy: MetadataPolicy,
) -> Result<bool> {
    let (parent, name) = root.parent_dir(path)?;
    let (target_parent, target_name) = root.existing_parent_dir(target_path)?;
    let target_stat = fstatat_optional(
        target_parent.as_raw_fd(),
        &target_name,
        libc::AT_SYMLINK_NOFOLLOW,
    )?
    .ok_or_else(|| "hardlink target does not exist".to_string())?;
    if stat_is_symlink(&target_stat) {
        return err("refusing to hardlink a symlink");
    }
    check_replace_target_at(parent.as_raw_fd(), &name, overwrite)?;

    if overwrite {
        let temp_name = match create_temp_hardlink_at(
            target_parent.as_raw_fd(),
            &target_name,
            parent.as_raw_fd(),
        ) {
            Ok(temp_name) => temp_name,
            Err(e) if metadata_policy == MetadataPolicy::BestEffort => {
                eprintln!(
                    "agesnap: warning: hardlink restore failed: {} -> {}: {e}",
                    path.display_lossy(),
                    target_path.display_lossy()
                );
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        };
        let mut temp_cleanup = RestoreTempCleanup::new(parent.as_raw_fd(), &temp_name);
        if let Some(st) =
            fstatat_optional(parent.as_raw_fd(), &temp_name, libc::AT_SYMLINK_NOFOLLOW)?
            && stat_is_symlink(&st)
        {
            return err("refusing to restore hardlink to symlink");
        }
        renameat_name(parent.as_raw_fd(), &temp_name, parent.as_raw_fd(), &name)?;
        temp_cleanup.disarm();
    } else {
        match linkat_name(
            target_parent.as_raw_fd(),
            &target_name,
            parent.as_raw_fd(),
            &name,
        ) {
            Ok(()) => {}
            Err(e) if metadata_policy == MetadataPolicy::BestEffort => {
                eprintln!(
                    "agesnap: warning: hardlink restore failed: {} -> {}: {e}",
                    path.display_lossy(),
                    target_path.display_lossy()
                );
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        if let Some(st) = fstatat_optional(parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW)?
            && stat_is_symlink(&st)
        {
            let _ = unlinkat_name(parent.as_raw_fd(), &name);
            return err("refusing to restore hardlink to symlink");
        }
    }
    Ok(true)
}

fn check_replace_target_at(parent_fd: libc::c_int, name: &CString, overwrite: bool) -> Result<()> {
    if let Some(st) = fstatat_optional(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW)? {
        if !overwrite {
            return err("restore target exists");
        }
        if stat_is_dir(&st) {
            return err("cannot overwrite directory");
        }
    }
    Ok(())
}

fn check_file_restore_target_at(
    parent_fd: libc::c_int,
    name: &CString,
    overwrite: bool,
) -> Result<()> {
    if let Some(st) = fstatat_optional(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW)? {
        if stat_is_dir(&st) {
            return err("cannot overwrite directory");
        }
        if !overwrite {
            return err("restore target exists");
        }
    }
    Ok(())
}

fn open_or_create_dir_at(parent_fd: libc::c_int, name: &CString) -> Result<File> {
    if let Some(dir) = open_dir_at_optional(parent_fd, name)? {
        return Ok(dir);
    }
    match mkdirat_name(parent_fd, name, 0o700) {
        Ok(()) => {}
        Err(e) if raw_os_error_is(&e, libc::EEXIST) => {}
        Err(e) => return Err(e.into()),
    }
    let dir = open_dir_at(parent_fd, name)?;
    fchmod_fd(dir.as_raw_fd(), 0o700)?;
    Ok(dir)
}

fn create_temp_file_at(parent_fd: libc::c_int, _final_name: &CString) -> Result<(CString, File)> {
    for _ in 0..100 {
        let temp_name = restore_temp_name()?;
        match open_file_create_new_at(parent_fd, &temp_name, 0o600) {
            Ok(file) => return Ok((temp_name, file)),
            Err(e) if raw_os_error_is(&e, libc::EEXIST) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    err("could not allocate restore temp path")
}

fn create_temp_symlink_at(parent_fd: libc::c_int, target: &CString) -> Result<CString> {
    for _ in 0..100 {
        let temp_name = restore_temp_name()?;
        match symlinkat_name_io(target, parent_fd, &temp_name) {
            Ok(()) => return Ok(temp_name),
            Err(e) if raw_os_error_is(&e, libc::EEXIST) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    err("could not allocate restore temp path")
}

fn create_temp_hardlink_at(
    target_parent_fd: libc::c_int,
    target_name: &CString,
    parent_fd: libc::c_int,
) -> std::io::Result<CString> {
    for _ in 0..100 {
        let temp_name = restore_temp_name().map_err(|e| std::io::Error::other(e.to_string()))?;
        match linkat_name_io(target_parent_fd, target_name, parent_fd, &temp_name) {
            Ok(()) => return Ok(temp_name),
            Err(e) if raw_os_error_is(&e, libc::EEXIST) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate restore temp path",
    ))
}

fn restore_temp_name() -> Result<CString> {
    let mut random = [0u8; 16];
    fill_random(&mut random)?;
    let mut name = Vec::new();
    name.extend_from_slice(b".agesnap-tmp-");
    name.extend_from_slice(hex(&random).as_bytes());
    Ok(CString::new(name)?)
}

fn c_component(component: &[u8]) -> Result<CString> {
    validate_component(component)?;
    CString::new(component).map_err(|_| "path component contains NUL".into())
}

fn fstatat_optional(
    parent_fd: libc::c_int,
    name: &CString,
    flags: libc::c_int,
) -> Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is a valid NUL-terminated C string and `stat` points to writable storage.
    let rc = unsafe { libc::fstatat(parent_fd, name.as_ptr(), stat.as_mut_ptr(), flags) };
    if rc == 0 {
        // SAFETY: `fstatat` returned success, so it initialized the `stat` buffer.
        Ok(Some(unsafe { stat.assume_init() }))
    } else {
        let e = std::io::Error::last_os_error();
        if raw_os_error_is(&e, libc::ENOENT) {
            Ok(None)
        } else {
            Err(e.into())
        }
    }
}

fn stat_is_dir(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

fn stat_is_file(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
}

fn stat_is_symlink(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

fn open_dir_at(parent_fd: libc::c_int, name: &CString) -> Result<File> {
    open_dir_at_optional(parent_fd, name)?
        .ok_or_else(|| "restore parent directory disappeared".into())
}

fn open_dir_at_optional(parent_fd: libc::c_int, name: &CString) -> Result<Option<File>> {
    // SAFETY: `name` is a valid NUL-terminated C string; the returned fd is checked below.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` was returned by `openat` and ownership is transferred to `File`.
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    } else {
        let e = std::io::Error::last_os_error();
        if raw_os_error_is(&e, libc::ENOENT) {
            Ok(None)
        } else {
            Err(e.into())
        }
    }
}

fn open_file_create_new_at(
    parent_fd: libc::c_int,
    name: &CString,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    // SAFETY: `name` is a valid NUL-terminated C string; the returned fd is checked below.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` was returned by `openat` and ownership is transferred to `File`.
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn open_file_read_at(parent_fd: libc::c_int, name: &CString) -> std::io::Result<File> {
    // SAFETY: `name` is a valid NUL-terminated C string; the returned fd is checked below.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` was returned by `openat` and ownership is transferred to `File`.
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn readlinkat_name(parent_fd: libc::c_int, name: &CString) -> Result<Vec<u8>> {
    let mut len = 256usize;
    loop {
        let mut target = vec![0u8; len];
        // SAFETY: `name` is NUL-terminated and `target` is valid writable storage.
        let rc = unsafe {
            libc::readlinkat(
                parent_fd,
                name.as_ptr(),
                target.as_mut_ptr().cast::<libc::c_char>(),
                target.len(),
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let written = rc as usize;
        if written < target.len() {
            target.truncate(written);
            return Ok(target);
        }
        if len > MAX_SYMLINK_TARGET_BYTES {
            return err("symlink target exceeds 1 MiB");
        }
        len = len.saturating_mul(2).min(MAX_SYMLINK_TARGET_BYTES + 1);
    }
}

fn mkdirat_name(parent_fd: libc::c_int, name: &CString, mode: libc::mode_t) -> std::io::Result<()> {
    // SAFETY: `name` is a valid NUL-terminated C string.
    let rc = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), mode) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unlinkat_name(parent_fd: libc::c_int, name: &CString) -> Result<()> {
    // SAFETY: `name` is a valid NUL-terminated C string.
    let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn renameat_name(
    old_parent_fd: libc::c_int,
    old_name: &CString,
    new_parent_fd: libc::c_int,
    new_name: &CString,
) -> Result<()> {
    // SAFETY: both names are valid NUL-terminated C strings.
    let rc = unsafe {
        libc::renameat(
            old_parent_fd,
            old_name.as_ptr(),
            new_parent_fd,
            new_name.as_ptr(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn linkat_name(
    old_parent_fd: libc::c_int,
    old_name: &CString,
    new_parent_fd: libc::c_int,
    new_name: &CString,
) -> Result<()> {
    linkat_name_io(old_parent_fd, old_name, new_parent_fd, new_name).map_err(Into::into)
}

fn linkat_name_io(
    old_parent_fd: libc::c_int,
    old_name: &CString,
    new_parent_fd: libc::c_int,
    new_name: &CString,
) -> std::io::Result<()> {
    // SAFETY: both names are valid NUL-terminated C strings.
    let rc = unsafe {
        libc::linkat(
            old_parent_fd,
            old_name.as_ptr(),
            new_parent_fd,
            new_name.as_ptr(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn symlinkat_name(target: &CString, parent_fd: libc::c_int, name: &CString) -> Result<()> {
    symlinkat_name_io(target, parent_fd, name).map_err(Into::into)
}

fn symlinkat_name_io(
    target: &CString,
    parent_fd: libc::c_int,
    name: &CString,
) -> std::io::Result<()> {
    // SAFETY: `target` and `name` are valid NUL-terminated C strings.
    let rc = unsafe { libc::symlinkat(target.as_ptr(), parent_fd, name.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn apply_file_dir_metadata_fd(
    fd: libc::c_int,
    meta: Meta,
    metadata_policy: MetadataPolicy,
) -> Result<()> {
    metadata_policy.handle("ownership restore", fchown_fd(fd, meta.uid, meta.gid))?;
    metadata_policy.handle("mode restore", fchmod_fd(fd, meta.mode & 0o7777))?;
    metadata_policy.handle("mtime restore", set_mtime_fd(fd, meta.mtime_ns))?;
    Ok(())
}

fn apply_symlink_metadata_at(
    parent_fd: libc::c_int,
    name: &CString,
    meta: Meta,
    metadata_policy: MetadataPolicy,
) -> Result<()> {
    metadata_policy.handle(
        "symlink ownership restore",
        fchownat_name(
            parent_fd,
            name,
            meta.uid,
            meta.gid,
            libc::AT_SYMLINK_NOFOLLOW,
        ),
    )?;
    metadata_policy.handle(
        "symlink mtime restore",
        set_mtime_at(parent_fd, name, meta.mtime_ns, libc::AT_SYMLINK_NOFOLLOW),
    )?;
    Ok(())
}

fn fchownat_name(
    parent_fd: libc::c_int,
    name: &CString,
    uid: u32,
    gid: u32,
    flags: libc::c_int,
) -> Result<()> {
    // SAFETY: `name` is a valid NUL-terminated C string.
    let rc = unsafe {
        libc::fchownat(
            parent_fd,
            name.as_ptr(),
            uid as libc::uid_t,
            gid as libc::gid_t,
            flags,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn fchmod_fd(fd: libc::c_int, mode: u32) -> Result<()> {
    // SAFETY: `fd` is expected to be an open file descriptor owned by the caller.
    let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn fchown_fd(fd: libc::c_int, uid: u32, gid: u32) -> Result<()> {
    // SAFETY: `fd` is expected to be an open file descriptor owned by the caller.
    let rc = unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn set_mtime_fd(fd: libc::c_int, mtime_ns: u64) -> Result<()> {
    let times = timespec_pair(mtime_ns);
    // SAFETY: `times` points to two valid timespec values for the duration of the call.
    let rc = unsafe { libc::futimens(fd, times.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn set_mtime_at(
    parent_fd: libc::c_int,
    name: &CString,
    mtime_ns: u64,
    flags: libc::c_int,
) -> Result<()> {
    let times = timespec_pair(mtime_ns);
    // SAFETY: `name` is a valid C string and `times` points to two valid timespec values.
    let rc = unsafe { libc::utimensat(parent_fd, name.as_ptr(), times.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn timespec_pair(mtime_ns: u64) -> [libc::timespec; 2] {
    let sec = (mtime_ns / 1_000_000_000) as libc::time_t;
    let nsec = (mtime_ns % 1_000_000_000) as libc::c_long;
    [
        libc::timespec {
            tv_sec: 0,
            // Restore promises mtime preservation only; leave atime unchanged.
            tv_nsec: libc::UTIME_OMIT as libc::c_long,
        },
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
    ]
}

fn raw_os_error_is(error: &std::io::Error, code: libc::c_int) -> bool {
    error.raw_os_error() == Some(code)
}

fn encode_chunk_plaintext(
    repo_id: &[u8; 32],
    id: &[u8; 32],
    chunk: &[u8],
    compression_level: i32,
) -> Result<Vec<u8>> {
    let (compression, payload) = if compression_level == 0 {
        (0u8, chunk.to_vec())
    } else {
        let compressed = zstd::stream::encode_all(Cursor::new(chunk), compression_level)?;
        if compressed.len() + 16 < chunk.len() {
            (1u8, compressed)
        } else {
            (0u8, chunk.to_vec())
        }
    };

    let mut out = Vec::new();
    out.extend_from_slice(CHUNK_MAGIC);
    push_u16(&mut out, 1);
    push_u16(&mut out, 0);
    out.extend_from_slice(repo_id);
    out.extend_from_slice(id);
    push_u32(
        &mut out,
        u32_checked(chunk.len(), "chunk plaintext length")?,
    );
    out.push(compression);
    out.extend_from_slice(&[0u8; 3]);
    push_bytes(&mut out, &payload)?;
    Ok(out)
}

fn decode_chunk_plaintext(
    repo_id: &[u8; 32],
    key: &[u8; 32],
    expected_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut r = Reader::new(plaintext);
    r.expect_bytes(CHUNK_MAGIC)?;
    let version = r.u16()?;
    let flags = r.u16()?;
    if version != 1 || flags != 0 {
        return err("unsupported chunk header");
    }
    let got_repo = r.array_32()?;
    if &got_repo != repo_id {
        return err("chunk repo id mismatch");
    }
    let id = r.array_32()?;
    if &id != expected_id {
        return err("chunk id field mismatch");
    }
    let plaintext_len = r.u32()? as usize;
    if plaintext_len > MAX_CHUNK_PLAINTEXT_BYTES {
        return err("chunk plaintext length exceeds 64 MiB");
    }
    let compression = r.u8()?;
    r.expect_bytes(&[0, 0, 0])?;
    let payload = r.bytes_limited(MAX_CHUNK_PLAINTEXT_BYTES, "chunk payload")?;
    r.finish()?;

    let chunk = match compression {
        0 => payload,
        1 => {
            let decoder = zstd::stream::read::Decoder::new(Cursor::new(payload))?;
            let mut limited = decoder.take((MAX_CHUNK_PLAINTEXT_BYTES as u64) + 1);
            let mut decoded = Vec::new();
            limited.read_to_end(&mut decoded)?;
            if decoded.len() > MAX_CHUNK_PLAINTEXT_BYTES {
                return err("decompressed chunk exceeds 64 MiB");
            }
            decoded
        }
        _ => return err("unknown chunk compression"),
    };
    if chunk.len() != plaintext_len {
        return err("chunk plaintext length mismatch");
    }
    let got_id = chunk_id(key, &chunk);
    if &got_id != expected_id {
        return err("keyed chunk verification failed");
    }
    Ok(chunk)
}

fn chunk_id(key: &[u8; 32], chunk: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity("agesnap-chunk-v1\0".len() + chunk.len());
    input.extend_from_slice(b"agesnap-chunk-v1\0");
    input.extend_from_slice(chunk);
    *blake3::keyed_hash(key, &input).as_bytes()
}

fn commit_mac(key: &[u8; 32], bytes_before_mac_line: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity("agesnap-commit-v1\0".len() + bytes_before_mac_line.len());
    input.extend_from_slice(b"agesnap-commit-v1\0");
    input.extend_from_slice(bytes_before_mac_line);
    *blake3::keyed_hash(key, &input).as_bytes()
}

fn age_encrypt(recipients: &[x25519::Recipient], plaintext: &[u8]) -> Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(encrypted)
}

fn age_decrypt(identities: &[x25519::Identity], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(Cursor::new(ciphertext))?;
    let mut reader = decryptor.decrypt(identities.iter().map(|i| i as &dyn age::Identity))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

fn parse_recipients(values: &[String]) -> Result<Vec<x25519::Recipient>> {
    values
        .iter()
        .map(|s| {
            s.parse::<x25519::Recipient>()
                .map_err(|e| format!("invalid age recipient {s}: {e}").into())
        })
        .collect()
}

fn read_identities(path: &Path) -> Result<Vec<x25519::Identity>> {
    let text = read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("AGE-SECRET-KEY-") {
            out.push(
                line.parse::<x25519::Identity>()
                    .map_err(|e| format!("invalid age identity: {e}"))?,
            );
        }
    }
    if out.is_empty() {
        return err("identity file contains no AGE-SECRET-KEY entries");
    }
    Ok(out)
}

fn fetch_public_config(client: &S3Client, repo: &S3Repo) -> Result<PublicConfig> {
    let bytes = s3_get(client, repo, "config.txt")?;
    let text = String::from_utf8(bytes)?;
    PublicConfig::parse(&text)
}

fn fetch_secrets(
    client: &S3Client,
    repo: &S3Repo,
    identities: &[x25519::Identity],
) -> Result<RepoSecrets> {
    let public_config = fetch_public_config(client, repo)?;
    let ciphertext = s3_get(client, repo, "secrets.age")?;
    let plaintext = age_decrypt(identities, &ciphertext)?;
    let text = String::from_utf8(plaintext)?;
    let secrets = RepoSecrets::parse(&text)?;
    if secrets.repo_id != public_config.repo_id {
        return err("secrets.age repo id does not match config.txt");
    }
    Ok(secrets)
}

fn s3_client(repo: &S3Repo, options: &S3ClientOptions) -> Result<S3Client> {
    S3Client::new(repo, options)
}

fn put_immutable(
    client: &S3Client,
    repo: &S3Repo,
    relative_key: &str,
    body: Vec<u8>,
) -> Result<bool> {
    let key = repo.key(relative_key);
    match client.put_if_absent(&key, &body)? {
        PutResult::Uploaded => Ok(true),
        PutResult::AlreadyExists => Ok(false),
    }
}

fn put_immutable_new(
    client: &S3Client,
    repo: &S3Repo,
    relative_key: &str,
    body: Vec<u8>,
) -> Result<()> {
    if put_immutable(client, repo, relative_key, body)? {
        Ok(())
    } else {
        err(format!("immutable object already exists: {relative_key}"))
    }
}

fn s3_get(client: &S3Client, repo: &S3Repo, relative_key: &str) -> Result<Vec<u8>> {
    let key = repo.key(relative_key);
    client.get(&key)
}

fn s3_delete_existing(client: &S3Client, repo: &S3Repo, relative_key: &str) -> Result<()> {
    s3_delete_any(client, repo, relative_key)
}

fn s3_delete_any(client: &S3Client, repo: &S3Repo, relative_key: &str) -> Result<()> {
    let key = repo.key(relative_key);
    client.delete(&key)
}

fn rollback_init_objects(client: &S3Client, repo: &S3Repo, keys: &[&str]) -> Result<()> {
    let mut first_error = None;
    for key in keys {
        if let Err(e) = s3_delete_any(client, repo, key)
            && first_error.is_none()
        {
            first_error = Some(e.to_string());
        }
    }
    if let Some(e) = first_error {
        return err(e);
    }
    Ok(())
}

fn list_keys(client: &S3Client, repo: &S3Repo, relative_prefix: &str) -> Result<Vec<String>> {
    let prefix = repo.key(relative_prefix);
    let mut out = Vec::new();
    for key in client.list_prefix(&prefix)? {
        if let Some(relative) = repo.strip(&key) {
            out.push(relative.to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn list_objects(
    client: &S3Client,
    repo: &S3Repo,
    relative_prefix: &str,
) -> Result<Vec<ListedObject>> {
    let prefix = repo.key(relative_prefix);
    let mut out = Vec::new();
    for object in client.list_prefix_entries(&prefix)? {
        if let Some(relative) = repo.strip(&object.key) {
            out.push(ListedObject {
                key: relative.to_string(),
                last_modified_unix_ns: object.last_modified_unix_ns,
            });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

fn list_commits(client: &S3Client, repo: &S3Repo) -> Result<Vec<CommitListing>> {
    let keys = list_keys(client, repo, "commits/")?;
    let mut commits = Vec::new();
    for key in keys {
        let bytes = s3_get(client, repo, &key)?;
        let text = String::from_utf8(bytes)?;
        let commit = Commit::parse_unverified(&text)?;
        commits.push(CommitListing {
            key,
            repo_id: commit.repo_id,
            snapshot_id: commit.snapshot_id,
            manifest_key: commit.manifest_key,
            created_unix_ns: commit.created_unix_ns,
            raw: text,
        });
    }
    commits.sort_by_key(|c| c.created_unix_ns);
    Ok(commits)
}

fn verified_commits(
    client: &S3Client,
    repo: &S3Repo,
    secrets: &RepoSecrets,
) -> Result<Vec<CommitListing>> {
    verified_commits_with_key(client, repo, secrets.repo_id, &secrets.commit_mac_key)
}

fn verified_commits_with_key(
    client: &S3Client,
    repo: &S3Repo,
    repo_id: [u8; 32],
    commit_mac_key: &[u8; 32],
) -> Result<Vec<CommitListing>> {
    let commits = list_commits(client, repo)?;
    let mut out = Vec::new();
    for commit in commits {
        if commit.repo_id != repo_id {
            return err(format!("commit repo id mismatch: {}", commit.key));
        }
        Commit::verify_text(&commit.raw, commit_mac_key)?;
        out.push(commit);
    }
    Ok(out)
}

fn latest_verified_commit(
    client: &S3Client,
    repo: &S3Repo,
    repo_id: [u8; 32],
    commit_mac_key: &[u8; 32],
) -> Result<Option<CommitListing>> {
    Ok(
        verified_commits_with_key(client, repo, repo_id, commit_mac_key)?
            .into_iter()
            .last(),
    )
}

fn fetch_verified_manifest(
    client: &S3Client,
    repo: &S3Repo,
    identities: &[x25519::Identity],
    secrets: &RepoSecrets,
    commit: &CommitListing,
) -> Result<SnapshotManifest> {
    let ciphertext = s3_get(client, repo, &commit.manifest_key)?;
    let snapshot_id = *blake3::hash(&ciphertext).as_bytes();
    if snapshot_id != commit.snapshot_id {
        return err(format!("manifest hash mismatch for {}", commit.key));
    }
    let plaintext = age_decrypt(identities, &ciphertext)?;
    let manifest = SnapshotManifest::parse(&plaintext)?;
    if manifest.repo_id != secrets.repo_id {
        return err("manifest repo id mismatch");
    }
    Ok(manifest)
}

// One coarse lock keeps S3 deletion races boring.
struct RepoLock<'a> {
    client: &'a S3Client,
    repo: S3Repo,
}

impl<'a> RepoLock<'a> {
    fn acquire(client: &'a S3Client, repo: &S3Repo, operation: &str) -> Result<Self> {
        let body = format!(
            "agesnap-lock-v1\ncreated_unix_ns={}\nhostname={}\npid={}\noperation={}\n",
            unix_nanos()?,
            std::env::var("HOSTNAME").unwrap_or_default(),
            std::process::id(),
            operation
        );
        let written = put_immutable(client, repo, "locks/repo.lock", body.into_bytes())?;
        if !written {
            return err("repository lock exists: locks/repo.lock");
        }
        Ok(Self {
            client,
            repo: repo.clone(),
        })
    }

    fn release(self) -> Result<()> {
        s3_delete_existing(self.client, &self.repo, "locks/repo.lock")
    }
}

#[derive(Clone)]
struct S3Client {
    bucket: Bucket,
    credentials: Credentials,
    agent: ureq::Agent,
}

#[derive(Clone, Debug)]
struct ListedObject {
    key: String,
    last_modified_unix_ns: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PutResult {
    Uploaded,
    AlreadyExists,
}

impl S3Client {
    fn new(repo: &S3Repo, options: &S3ClientOptions) -> Result<Self> {
        let endpoint = options.endpoint.as_deref().ok_or_else(|| {
            "missing s3.endpoint; set it in --config or pass --s3-endpoint".to_string()
        })?;
        let region = options.region.as_deref().ok_or_else(|| {
            "missing s3.region; set it in --config or pass --s3-region".to_string()
        })?;
        let url_style = if options.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let bucket = Bucket::new(
            endpoint.parse()?,
            url_style,
            repo.bucket.clone(),
            region.to_string(),
        )
        .map_err(|e| format!("invalid S3 bucket configuration: {e:?}"))?;
        let credentials = Credentials::from_env().ok_or_else(|| {
            "missing AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY in environment".to_string()
        })?;
        Ok(Self {
            bucket,
            credentials,
            agent: ureq::Agent::new_with_defaults(),
        })
    }

    fn put_if_absent(&self, key: &str, body: &[u8]) -> Result<PutResult> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let mut action = self.bucket.put_object(Some(&self.credentials), key);
            // A 412 from conditional PutObject is the dedupe path.
            action.headers_mut().insert("if-none-match", "*");
            let url = action.sign(Duration::from_secs(S3_SIGNED_URL_TTL_SECS));
            let result = self
                .agent
                .put(url.as_str())
                .header("if-none-match", "*")
                .send(body);
            match result {
                Ok(response) => {
                    let code = response.status().as_u16();
                    if matches!(code, 200 | 201 | 204) {
                        return Ok(PutResult::Uploaded);
                    }
                    return err(format!("put {key} failed: HTTP {code}"));
                }
                Err(ureq::Error::StatusCode(412)) => return Ok(PutResult::AlreadyExists),
                Err(ureq::Error::StatusCode(409)) if attempts < 4 => s3_backoff(attempts),
                Err(e) if attempts < 4 && is_retryable_http_error(&e) => s3_backoff(attempts),
                Err(e) => return err(format!("put {key} failed: {e}")),
            }
        }
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let action = self.bucket.get_object(Some(&self.credentials), key);
        let url = action.sign(Duration::from_secs(S3_SIGNED_URL_TTL_SECS));
        let mut response = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(|e| format!("get {key} failed: {e}"))?;
        response
            .body_mut()
            .with_config()
            .limit(S3_MAX_READ_BYTES)
            .read_to_vec()
            .map_err(|e| format!("read {key} failed: {e}").into())
    }

    #[allow(dead_code)]
    fn head(&self, key: &str) -> Result<bool> {
        let action = self.bucket.head_object(Some(&self.credentials), key);
        let url = action.sign(Duration::from_secs(S3_SIGNED_URL_TTL_SECS));
        match self.agent.head(url.as_str()).call() {
            Ok(_) => Ok(true),
            Err(ureq::Error::StatusCode(404)) => Ok(false),
            Err(e) => err(format!("head {key} failed: {e}")),
        }
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .list_prefix_entries(prefix)?
            .into_iter()
            .map(|object| object.key)
            .collect())
    }

    fn list_prefix_entries(&self, prefix: &str) -> Result<Vec<ListedObject>> {
        let mut token: Option<String> = None;
        let mut out = Vec::new();
        loop {
            let mut action = self.bucket.get_object(Some(&self.credentials), "");
            action.query_mut().insert("list-type", "2");
            // Ask S3 to keep awkward object keys out of raw XML text.
            action.query_mut().insert("encoding-type", "url");
            action.query_mut().insert("prefix", prefix.to_string());
            if let Some(token) = &token {
                action
                    .query_mut()
                    .insert("continuation-token", token.clone());
            }
            let url = action.sign(Duration::from_secs(S3_SIGNED_URL_TTL_SECS));
            let mut response = self
                .agent
                .get(url.as_str())
                .call()
                .map_err(|e| format!("list {prefix} failed: {e}"))?;
            let bytes = response
                .body_mut()
                .with_config()
                .limit(S3_MAX_READ_BYTES)
                .read_to_vec()
                .map_err(|e| format!("read list {prefix} failed: {e}"))?;
            let xml = String::from_utf8(bytes)?;
            let page = parse_list_objects_v2_xml(&xml)?;
            out.extend(page.objects);
            if page.is_truncated {
                token = Some(page.next_continuation_token.ok_or_else(|| {
                    "S3 listing was truncated without continuation token".to_string()
                })?);
            } else {
                break;
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let action = self.bucket.delete_object(Some(&self.credentials), key);
        let url = action.sign(Duration::from_secs(S3_SIGNED_URL_TTL_SECS));
        match self.agent.delete(url.as_str()).call() {
            Ok(_) | Err(ureq::Error::StatusCode(404)) => Ok(()),
            Err(e) => err(format!("delete {key} failed: {e}")),
        }
    }
}

fn s3_backoff(attempts: u32) {
    thread::sleep(Duration::from_millis(100 * u64::from(attempts)));
}

fn is_retryable_http_error(error: &ureq::Error) -> bool {
    !matches!(error, ureq::Error::StatusCode(code) if *code < 500)
}

struct ListPage {
    objects: Vec<ListedObject>,
    next_continuation_token: Option<String>,
    is_truncated: bool,
}

fn parse_list_objects_v2_xml(xml: &str) -> Result<ListPage> {
    let encoding_type = xml_first_text(xml, "EncodingType")?;
    let url_encoded_keys = match encoding_type.as_deref() {
        Some("url") => true,
        Some(value) => return err(format!("unsupported S3 list encoding type: {value}")),
        None => false,
    };
    let mut objects = Vec::new();
    for contents in xml_blocks(xml, "Contents") {
        let Some(mut key) = xml_first_text(contents, "Key")? else {
            continue;
        };
        if url_encoded_keys {
            key = percent_decode_utf8(&key)?;
        }
        let last_modified_unix_ns = xml_first_text(contents, "LastModified")?
            .map(|value| parse_s3_last_modified_unix_ns(&value))
            .transpose()?;
        objects.push(ListedObject {
            key,
            last_modified_unix_ns,
        });
    }
    let next_continuation_token = xml_first_text(xml, "NextContinuationToken")?;
    let is_truncated = xml_first_text(xml, "IsTruncated")?
        .as_deref()
        .map_or(Ok(false), parse_bool)?;
    Ok(ListPage {
        objects,
        next_continuation_token,
        is_truncated,
    })
}

fn xml_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let mut rest = xml;
    let mut out = Vec::new();
    while let Some(start) = rest.find(&start_tag) {
        let after_start = &rest[start + start_tag.len()..];
        let Some(end) = after_start.find(&end_tag) else {
            break;
        };
        out.push(&after_start[..end]);
        rest = &after_start[end + end_tag.len()..];
    }
    out
}

fn xml_first_text(xml: &str, tag: &str) -> Result<Option<String>> {
    let Some(text) = xml_blocks(xml, tag).into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(decode_xml_entities(text)?))
}

fn decode_xml_entities(text: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after_amp = &rest[pos + 1..];
        let end = after_amp
            .find(';')
            .ok_or_else(|| "unterminated XML entity".to_string())?;
        let entity = &after_amp[..end];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let code = u32::from_str_radix(&entity[2..], 16)
                    .map_err(|_| format!("invalid XML entity: &{entity};"))?;
                let ch = char::from_u32(code)
                    .ok_or_else(|| format!("invalid XML entity: &{entity};"))?;
                out.push(ch);
            }
            _ if entity.starts_with('#') => {
                let code = entity[1..]
                    .parse::<u32>()
                    .map_err(|_| format!("invalid XML entity: &{entity};"))?;
                let ch = char::from_u32(code)
                    .ok_or_else(|| format!("invalid XML entity: &{entity};"))?;
                out.push(ch);
            }
            _ => return err(format!("unsupported XML entity: &{entity};")),
        }
        rest = &after_amp[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn percent_decode_utf8(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return err(format!("invalid percent encoding in S3 list key: {value}"));
            }
            let hi = hex_nibble(bytes[idx + 1])
                .ok_or_else(|| format!("invalid percent encoding in S3 list key: {value}"))?;
            let lo = hex_nibble(bytes[idx + 2])
                .ok_or_else(|| format!("invalid percent encoding in S3 list key: {value}"))?;
            out.push((hi << 4) | lo);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    String::from_utf8(out).map_err(|e| format!("invalid UTF-8 in S3 list key: {e}").into())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct S3Repo {
    bucket: String,
    prefix: String,
}

impl S3Repo {
    fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("s3://")
            .ok_or_else(|| "repo must start with s3://".to_string())?;
        let (bucket, prefix) = match rest.split_once('/') {
            Some((bucket, prefix)) => (bucket, prefix.trim_matches('/')),
            None => (rest, ""),
        };
        if bucket.is_empty() {
            return err("S3 bucket is empty");
        }
        if !prefix.is_empty()
            && prefix.len() + 1 + MAX_GENERATED_S3_KEY_BYTES > S3_MAX_OBJECT_KEY_BYTES
        {
            return err(format!(
                "S3 repository prefix exceeds {} byte limit",
                S3_MAX_OBJECT_KEY_BYTES - 1 - MAX_GENERATED_S3_KEY_BYTES
            ));
        }
        Ok(Self {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
        })
    }

    fn key(&self, relative: &str) -> String {
        if self.prefix.is_empty() {
            relative.trim_start_matches('/').to_string()
        } else {
            format!("{}/{}", self.prefix, relative.trim_start_matches('/'))
        }
    }

    fn strip<'a>(&self, full_key: &'a str) -> Option<&'a str> {
        if self.prefix.is_empty() {
            Some(full_key)
        } else {
            full_key.strip_prefix(&(self.prefix.clone() + "/"))
        }
    }
}

impl std::fmt::Display for S3Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.prefix.is_empty() {
            write!(f, "s3://{}", self.bucket)
        } else {
            write!(f, "s3://{}/{}", self.bucket, self.prefix)
        }
    }
}

#[derive(Clone)]
struct Capability {
    repo: S3Repo,
    repo_id: [u8; 32],
    recipients: Vec<String>,
    min_chunk: u32,
    target_chunk: u32,
    max_chunk: u32,
    compression_level: i32,
    chunk_id_key: [u8; 32],
    commit_mac_key: [u8; 32],
    gear_seed: [u8; 32],
}

impl Capability {
    fn encode(&self) -> String {
        let mut out = String::new();
        out.push_str("agesnap-capability-v1\n");
        out.push_str(&format!("repo={}\n", self.repo));
        out.push_str(&format!("repo_id={}\n", hex(&self.repo_id)));
        out.push_str(&format!("min_chunk={}\n", self.min_chunk));
        out.push_str(&format!("target_chunk={}\n", self.target_chunk));
        out.push_str(&format!("max_chunk={}\n", self.max_chunk));
        out.push_str(&format!("compression_level={}\n", self.compression_level));
        out.push_str(&format!("chunk_id_key={}\n", hex(&self.chunk_id_key)));
        out.push_str(&format!("commit_mac_key={}\n", hex(&self.commit_mac_key)));
        out.push_str(&format!("gear_seed={}\n", hex(&self.gear_seed)));
        for r in &self.recipients {
            out.push_str(&format!("recipient={r}\n"));
        }
        out
    }

    fn parse(text: &str) -> Result<Self> {
        let kv = KeyValues::parse_with_repeated(text, "agesnap-capability-v1", &["recipient"])?;
        kv.reject_unknown(&[
            "repo",
            "repo_id",
            "min_chunk",
            "target_chunk",
            "max_chunk",
            "compression_level",
            "chunk_id_key",
            "commit_mac_key",
            "gear_seed",
            "recipient",
        ])?;
        let capability = Self {
            repo: S3Repo::parse(kv.required("repo")?)?,
            repo_id: parse_hex_32(kv.required("repo_id")?)?,
            min_chunk: kv.required("min_chunk")?.parse()?,
            target_chunk: kv.required("target_chunk")?.parse()?,
            max_chunk: kv.required("max_chunk")?.parse()?,
            compression_level: kv
                .optional("compression_level")
                .map(parse_compression_level)
                .transpose()?
                .unwrap_or(DEFAULT_ZSTD_LEVEL),
            chunk_id_key: parse_hex_32(kv.required("chunk_id_key")?)?,
            commit_mac_key: parse_hex_32(kv.required("commit_mac_key")?)?,
            gear_seed: parse_hex_32(kv.required("gear_seed")?)?,
            recipients: kv.all("recipient").to_vec(),
        };
        validate_chunk_settings(
            capability.min_chunk,
            capability.target_chunk,
            capability.max_chunk,
        )?;
        Ok(capability)
    }
}

struct PublicConfig {
    repo_id: [u8; 32],
    created_unix_ns: u64,
    min_chunk: u32,
    target_chunk: u32,
    max_chunk: u32,
}

impl PublicConfig {
    fn encode(&self) -> String {
        let mut out = String::new();
        out.push_str("agesnap-repo-v1\n");
        out.push_str(&format!("repo_id={}\n", hex(&self.repo_id)));
        out.push_str(&format!("created_unix_nanos={}\n", self.created_unix_ns));
        out.push_str("chunker=gear\n");
        out.push_str(&format!("chunk_min={}\n", self.min_chunk));
        out.push_str(&format!("chunk_avg={}\n", self.target_chunk));
        out.push_str(&format!("chunk_max={}\n", self.max_chunk));
        out.push_str("compression=zstd\n");
        out.push_str("archive_format=asar-v1\n");
        out
    }

    fn parse(text: &str) -> Result<Self> {
        if text.lines().next().map(str::trim) == Some("agesnap-config-v1") {
            let kv = KeyValues::parse(text, "agesnap-config-v1")?;
            kv.reject_unknown(&[
                "repo_id",
                "min_chunk",
                "target_chunk",
                "max_chunk",
                "recipient",
            ])?;
            let config = Self {
                repo_id: parse_hex_32(kv.required("repo_id")?)?,
                created_unix_ns: 0,
                min_chunk: kv.required("min_chunk")?.parse()?,
                target_chunk: kv.required("target_chunk")?.parse()?,
                max_chunk: kv.required("max_chunk")?.parse()?,
            };
            validate_chunk_settings(config.min_chunk, config.target_chunk, config.max_chunk)?;
            return Ok(config);
        }
        let kv = KeyValues::parse(text, "agesnap-repo-v1")?;
        kv.reject_unknown(&[
            "repo_id",
            "created_unix_nanos",
            "chunker",
            "chunk_min",
            "chunk_avg",
            "chunk_max",
            "compression",
            "archive_format",
        ])?;
        if kv.required("chunker")? != "gear" {
            return err("unsupported repo chunker");
        }
        if kv.required("compression")? != "zstd" {
            return err("unsupported repo compression");
        }
        if kv.required("archive_format")? != "asar-v1" {
            return err("unsupported archive format");
        }
        let config = Self {
            repo_id: parse_hex_32(kv.required("repo_id")?)?,
            created_unix_ns: kv.required("created_unix_nanos")?.parse()?,
            min_chunk: kv.required("chunk_min")?.parse()?,
            target_chunk: kv.required("chunk_avg")?.parse()?,
            max_chunk: kv.required("chunk_max")?.parse()?,
        };
        validate_chunk_settings(config.min_chunk, config.target_chunk, config.max_chunk)?;
        Ok(config)
    }
}

#[derive(Clone)]
struct RepoSecrets {
    repo_id: [u8; 32],
    chunk_id_key: [u8; 32],
    commit_mac_key: [u8; 32],
    gear_seed: [u8; 32],
}

impl RepoSecrets {
    fn encode(&self) -> String {
        format!(
            "agesnap-secrets-v1\nrepo_id={}\nchunk_id_key={}\ncommit_mac_key={}\ngear_seed={}\n",
            hex(&self.repo_id),
            hex(&self.chunk_id_key),
            hex(&self.commit_mac_key),
            hex(&self.gear_seed)
        )
    }

    fn parse(text: &str) -> Result<Self> {
        let kv = KeyValues::parse(text, "agesnap-secrets-v1")?;
        kv.reject_unknown(&["repo_id", "chunk_id_key", "commit_mac_key", "gear_seed"])?;
        Ok(Self {
            repo_id: parse_hex_32(kv.required("repo_id")?)?,
            chunk_id_key: parse_hex_32(kv.required("chunk_id_key")?)?,
            commit_mac_key: parse_hex_32(kv.required("commit_mac_key")?)?,
            gear_seed: parse_hex_32(kv.required("gear_seed")?)?,
        })
    }
}

struct KeyValues {
    items: Vec<(String, String)>,
}

impl KeyValues {
    fn parse(text: &str, magic: &str) -> Result<Self> {
        Self::parse_with_repeated(text, magic, &[])
    }

    fn parse_with_repeated(text: &str, magic: &str, repeated: &[&str]) -> Result<Self> {
        let mut lines = text.lines();
        let first = lines
            .by_ref()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'));
        if first != Some(magic) {
            return err(format!("expected {magic}"));
        }
        let mut items = Vec::new();
        let mut seen = HashSet::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("invalid key-value line: {line}"))?;
            let k = k.trim();
            let v = v.trim();
            if k.is_empty() {
                return err("empty key in key-value file");
            }
            if !repeated.contains(&k) && !seen.insert(k.to_string()) {
                return err(format!("duplicate key: {k}"));
            }
            items.push((k.to_string(), v.to_string()));
        }
        Ok(Self { items })
    }

    fn reject_unknown(&self, allowed: &[&str]) -> Result<()> {
        for (key, _) in &self.items {
            if !allowed.contains(&key.as_str()) {
                return err(format!("unknown key: {key}"));
            }
        }
        Ok(())
    }

    fn required(&self, key: &str) -> Result<&str> {
        self.items
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| format!("missing {key}").into())
    }

    fn optional(&self, key: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, key: &str) -> Vec<String> {
        self.items
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
struct Commit {
    repo_id: [u8; 32],
    snapshot_id: [u8; 32],
    manifest_key: String,
    created_unix_ns: u64,
    parent_snapshot_id: Option<[u8; 32]>,
    mac: [u8; 32],
}

impl Commit {
    fn encode_signed(&self, key: &[u8; 32]) -> String {
        let mut out = String::new();
        out.push_str("agesnap-commit-v1\n");
        out.push_str(&format!("repo_id={}\n", hex(&self.repo_id)));
        out.push_str(&format!("snapshot_id={}\n", hex(&self.snapshot_id)));
        out.push_str(&format!("manifest={}\n", self.manifest_key));
        out.push_str(&format!("created_unix_ns={}\n", self.created_unix_ns));
        out.push_str("parent_snapshot_id=");
        if let Some(parent) = self.parent_snapshot_id {
            out.push_str(&hex(&parent));
        }
        out.push('\n');
        let mac = commit_mac(key, out.as_bytes());
        out.push_str(&format!("mac={}\n", hex(&mac)));
        out
    }

    fn parse_unverified(text: &str) -> Result<Self> {
        let _ = commit_mac_marker_pos(text)?;
        let kv = KeyValues::parse(text, "agesnap-commit-v1")?;
        kv.reject_unknown(&[
            "repo_id",
            "snapshot_id",
            "manifest",
            "created_unix_ns",
            "parent_snapshot_id",
            "mac",
        ])?;
        let parent = kv.required("parent_snapshot_id")?;
        let snapshot_id = parse_hex_32(kv.required("snapshot_id")?)?;
        let commit_manifest_key = kv.required("manifest")?.to_string();
        let expected_manifest_key = manifest_key(&snapshot_id);
        if commit_manifest_key != expected_manifest_key {
            return err("commit manifest path does not match snapshot id");
        }
        let created_unix_ns: u64 = kv.required("created_unix_ns")?.parse()?;
        if created_unix_ns == 0 {
            return err("commit created_unix_ns must be non-zero");
        }
        if let Ok(now) = unix_nanos() {
            let max_future = now.saturating_add(366 * 24 * 60 * 60 * 1_000_000_000);
            if created_unix_ns > max_future {
                return err("commit created_unix_ns is too far in the future");
            }
        }
        Ok(Self {
            repo_id: parse_hex_32(kv.required("repo_id")?)?,
            snapshot_id,
            manifest_key: commit_manifest_key,
            created_unix_ns,
            parent_snapshot_id: if parent.is_empty() {
                None
            } else {
                Some(parse_hex_32(parent)?)
            },
            mac: parse_hex_32(kv.required("mac")?)?,
        })
    }

    fn verify_text(text: &str, key: &[u8; 32]) -> Result<()> {
        let parsed = Self::parse_unverified(text)?;
        let pos = commit_mac_marker_pos(text)?;
        let before_mac = &text.as_bytes()[..pos + 1];
        let got = commit_mac(key, before_mac);
        if got != parsed.mac {
            return err("commit MAC verification failed");
        }
        Ok(())
    }
}

fn commit_mac_marker_pos(text: &str) -> Result<usize> {
    let marker = "\nmac=";
    let pos = text
        .rfind(marker)
        .ok_or_else(|| "commit missing mac line".to_string())?;
    let mac_line = &text[pos + 1..];
    if !mac_line.ends_with('\n') || mac_line[..mac_line.len() - 1].contains('\n') {
        return err("commit mac line must be last");
    }
    Ok(pos)
}

#[derive(Clone)]
struct CommitListing {
    key: String,
    repo_id: [u8; 32],
    snapshot_id: [u8; 32],
    manifest_key: String,
    created_unix_ns: u64,
    raw: String,
}

#[derive(Clone)]
struct SnapshotManifest {
    repo_id: [u8; 32],
    created_unix_ns: u64,
    archive_len: u64,
    name: Vec<u8>,
    tags: Vec<Vec<u8>>,
    roots: Vec<PathParts>,
    files: u64,
    directories: u64,
    symlinks: u64,
    hardlinks: u64,
    logical_bytes: u64,
    chunk_refs: Vec<ChunkRef>,
}

impl SnapshotManifest {
    fn encode(&self) -> Result<Vec<u8>> {
        // Do not write a manifest that the parser would reject later.
        self.validate_for_encode()?;
        let mut out = Vec::new();
        out.extend_from_slice(MANIFEST_MAGIC);
        push_u16(&mut out, 1);
        push_u16(&mut out, 0);
        out.extend_from_slice(&self.repo_id);
        push_u64(&mut out, self.created_unix_ns);
        push_u64(&mut out, self.archive_len);
        push_bytes(&mut out, &self.name)?;
        push_vec_bytes(&mut out, &self.tags)?;
        push_u32(
            &mut out,
            u32_checked(self.roots.len(), "manifest roots count")?,
        );
        for root in &self.roots {
            push_path(&mut out, root)?;
        }
        push_u64(&mut out, self.files);
        push_u64(&mut out, self.directories);
        push_u64(&mut out, self.symlinks);
        push_u64(&mut out, self.hardlinks);
        push_u64(&mut out, self.logical_bytes);
        push_u32(
            &mut out,
            u32_checked(self.chunk_refs.len(), "chunk ref count")?,
        );
        for c in &self.chunk_refs {
            out.extend_from_slice(&c.id);
            push_u32(&mut out, c.plaintext_len);
        }
        Ok(out)
    }

    fn validate_for_encode(&self) -> Result<()> {
        if self.name.len() > MAX_MANIFEST_TEXT_BYTES {
            return err("manifest snapshot name exceeds maximum length");
        }
        if self.tags.len() > MAX_MANIFEST_TAGS {
            return err("manifest has too many tags");
        }
        for tag in &self.tags {
            if tag.len() > MAX_MANIFEST_TEXT_BYTES {
                return err("manifest tag exceeds maximum length");
            }
        }
        if self.roots.len() > MAX_PATH_COMPONENTS {
            return err("manifest has too many roots");
        }
        for root in &self.roots {
            root.validate()?;
        }
        if self.chunk_refs.len() > MAX_MANIFEST_CHUNKS {
            return err("manifest has too many chunk references");
        }
        for chunk_ref in &self.chunk_refs {
            if chunk_ref.plaintext_len as usize > MAX_CHUNK_PLAINTEXT_BYTES {
                return err("manifest chunk plaintext length exceeds 64 MiB");
            }
        }
        Ok(())
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.expect_bytes(MANIFEST_MAGIC)?;
        let version = r.u16()?;
        let flags = r.u16()?;
        if version != 1 || flags != 0 {
            return err("unsupported manifest header");
        }
        let repo_id = r.array_32()?;
        let created_unix_ns = r.u64()?;
        let archive_len = r.u64()?;
        let name = r.bytes_limited(MAX_MANIFEST_TEXT_BYTES, "manifest snapshot name")?;
        let tags =
            r.vec_bytes_limited(MAX_MANIFEST_TAGS, MAX_MANIFEST_TEXT_BYTES, "manifest tags")?;
        let root_count = r.u32()? as usize;
        if root_count > MAX_PATH_COMPONENTS {
            return err("manifest has too many roots");
        }
        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            roots.push(r.path()?);
        }
        let files = r.u64()?;
        let directories = r.u64()?;
        let symlinks = r.u64()?;
        let hardlinks = r.u64()?;
        let logical_bytes = r.u64()?;
        let chunk_count = r.u32()? as usize;
        if chunk_count > MAX_MANIFEST_CHUNKS {
            return err("manifest has too many chunk references");
        }
        let mut chunk_refs = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            let id = r.array_32()?;
            let plaintext_len = r.u32()?;
            if plaintext_len as usize > MAX_CHUNK_PLAINTEXT_BYTES {
                return err("manifest chunk plaintext length exceeds 64 MiB");
            }
            chunk_refs.push(ChunkRef { id, plaintext_len });
        }
        r.finish()?;
        Ok(Self {
            repo_id,
            created_unix_ns,
            archive_len,
            name,
            tags,
            roots,
            files,
            directories,
            symlinks,
            hardlinks,
            logical_bytes,
            chunk_refs,
        })
    }
}

#[derive(Clone)]
struct ChunkRef {
    id: [u8; 32],
    plaintext_len: u32,
}

#[derive(Default)]
struct ScanStats {
    files: u64,
    directories: u64,
    symlinks: u64,
    hardlinks: u64,
    skipped_files: u64,
    logical_bytes: u64,
}

#[derive(Clone, Copy)]
struct Meta {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: u64,
}

impl Meta {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        let sec = meta.mtime();
        let nsec = meta.mtime_nsec();
        let mtime_ns = if sec < 0 {
            0
        } else {
            sec as u64 * 1_000_000_000 + nsec.max(0) as u64
        };
        Self {
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime_ns,
        }
    }
}

fn meta_from_stat(st: &libc::stat) -> Meta {
    let sec = st.st_mtime;
    let nsec = st.st_mtime_nsec;
    let mtime_ns = if sec < 0 {
        0
    } else {
        sec as u64 * 1_000_000_000 + nsec.max(0) as u64
    };
    Meta {
        mode: st.st_mode,
        uid: st.st_uid,
        gid: st.st_gid,
        mtime_ns,
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct PathParts(Vec<Vec<u8>>);

impl PathParts {
    fn validate(&self) -> Result<()> {
        if self.0.is_empty() {
            return err("path has no components");
        }
        if self.0.len() > MAX_PATH_COMPONENTS {
            return err("path has too many components");
        }
        for component in &self.0 {
            validate_component(component)?;
        }
        Ok(())
    }

    fn is_prefix_of(&self, path: &PathParts) -> bool {
        self.0.len() <= path.0.len()
            && self
                .0
                .iter()
                .zip(&path.0)
                .all(|(left, right)| left == right)
    }

    fn display_lossy(&self) -> String {
        let mut out = String::new();
        for (idx, component) in self.0.iter().enumerate() {
            if idx > 0 {
                out.push('/');
            }
            out.push_str(&String::from_utf8_lossy(component));
        }
        out
    }
}

fn display_bytes_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn display_byte_list_lossy(values: &[Vec<u8>]) -> String {
    values
        .iter()
        .map(|value| display_bytes_lossy(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn display_roots_lossy(paths: &[PathParts]) -> String {
    paths
        .iter()
        .map(PathParts::display_lossy)
        .collect::<Vec<_>>()
        .join(",")
}

fn validate_component(component: &[u8]) -> Result<()> {
    if component.is_empty() {
        return err("path component is empty");
    }
    if component.len() > MAX_PATH_COMPONENT_BYTES {
        return err("path component exceeds 4096 bytes");
    }
    if component == b"." || component == b".." {
        return err("unsafe path component");
    }
    if component.contains(&0) || component.contains(&b'/') {
        return err("invalid path component");
    }
    Ok(())
}

fn parse_restore_path_arg(path: &OsStr) -> Result<PathParts> {
    let bytes = path.as_bytes();
    if bytes.starts_with(b"/") {
        return err("restore --path must be an archive-relative path");
    }
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &bytes[..end];
    if trimmed.is_empty() {
        return err("restore --path is empty");
    }
    let mut components = Vec::new();
    for component in trimmed.split(|b| *b == b'/') {
        validate_component(component)?;
        components.push(component.to_vec());
    }
    Ok(PathParts(components))
}

fn archive_root_name(idx: usize, root: &Path, used: &mut HashSet<Vec<u8>>) -> Vec<u8> {
    let mut base = root
        .file_name()
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"root".to_vec());
    if base == b"." || base == b".." || base.contains(&0) || base.contains(&b'/') {
        base = b"root".to_vec();
    }
    if used.insert(base.clone()) {
        return base;
    }
    let mut candidate = base;
    candidate.extend_from_slice(format!("-{}", idx + 1).as_bytes());
    while !used.insert(candidate.clone()) {
        candidate.push(b'_');
    }
    candidate
}

struct GearChunker<F>
where
    F: FnMut(Vec<u8>) -> Result<()>,
{
    table: [u64; 256],
    min: usize,
    max: usize,
    mask: u64,
    current: Vec<u8>,
    fp: u64,
    total_len: u64,
    on_chunk: F,
}

impl<F> GearChunker<F>
where
    F: FnMut(Vec<u8>) -> Result<()>,
{
    fn new(seed: [u8; 32], min: u32, target: u32, max: u32, on_chunk: F) -> Result<Self> {
        validate_chunk_settings(min, target, max)?;
        let bits = 31 - target.leading_zeros();
        let mask = (1u64 << bits) - 1;
        let mut table = [0u64; 256];
        for i in 0..256u16 {
            let mut input = Vec::new();
            input.extend_from_slice(b"agesnap-gear-v1\0");
            input.push(i as u8);
            let h = blake3::keyed_hash(&seed, &input);
            let mut b = [0u8; 8];
            b.copy_from_slice(&h.as_bytes()[..8]);
            table[i as usize] = u64::from_be_bytes(b);
        }
        Ok(Self {
            table,
            min: min as usize,
            max: max as usize,
            mask,
            current: Vec::with_capacity(target as usize),
            fp: 0,
            total_len: 0,
            on_chunk,
        })
    }

    fn finish(mut self) -> Result<()> {
        if !self.current.is_empty() {
            self.emit()?;
        }
        Ok(())
    }

    fn emit(&mut self) -> std::io::Result<()> {
        let chunk = std::mem::take(&mut self.current);
        (self.on_chunk)(chunk).map_err(|e| std::io::Error::other(e.to_string()))?;
        self.fp = 0;
        Ok(())
    }
}

impl<F> Write for GearChunker<F>
where
    F: FnMut(Vec<u8>) -> Result<()>,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for &b in buf {
            self.current.push(b);
            self.total_len += 1;
            self.fp = (self.fp << 1).wrapping_add(self.table[b as usize]);
            if self.current.len() >= self.max
                || (self.current.len() >= self.min && (self.fp & self.mask) == 0)
            {
                self.emit()?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn finish(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            err("trailing bytes after top-level parse")
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self
            .pos
            .checked_add(n)
            .is_none_or(|end| end > self.bytes.len())
        {
            return err("unexpected end of input");
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<()> {
        let got = self.take(expected.len())?;
        if got == expected {
            Ok(())
        } else {
            err("magic or reserved bytes mismatch")
        }
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut b = [0u8; 2];
        b.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(b))
    }

    fn u32(&mut self) -> Result<u32> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(b))
    }

    fn u64(&mut self) -> Result<u64> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(b))
    }

    fn array_32(&mut self) -> Result<[u8; 32]> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn bytes_limited(&mut self, max_len: usize, label: &str) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > max_len {
            return err(format!("{label} exceeds maximum length"));
        }
        Ok(self.take(n)?.to_vec())
    }

    fn vec_bytes_limited(
        &mut self,
        max_count: usize,
        max_item_len: usize,
        label: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let n = self.u32()? as usize;
        if n > max_count {
            return err(format!("{label} has too many entries"));
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.bytes_limited(max_item_len, label)?);
        }
        Ok(out)
    }

    fn path(&mut self) -> Result<PathParts> {
        let n = self.u16()? as usize;
        if n == 0 {
            return err("path has no components");
        }
        if n > MAX_PATH_COMPONENTS {
            return err("path has too many components");
        }
        let mut components = Vec::with_capacity(n);
        for _ in 0..n {
            let len = self.u16()? as usize;
            let c = self.take(len)?.to_vec();
            validate_component(&c)?;
            components.push(c);
        }
        Ok(PathParts(components))
    }
}

fn write_u16(out: &mut dyn Write, v: u16) -> Result<()> {
    out.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_u64(out: &mut dyn Write, v: u64) -> Result<()> {
    out.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_bytes(out: &mut dyn Write, bytes: &[u8]) -> Result<()> {
    write_u32(out, u32_checked(bytes.len(), "byte string length")?)?;
    out.write_all(bytes)?;
    Ok(())
}

fn write_u32(out: &mut dyn Write, v: u32) -> Result<()> {
    out.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_path(out: &mut dyn Write, path: &PathParts) -> Result<()> {
    path.validate()?;
    write_u16(out, u16_checked(path.0.len(), "path component count")?)?;
    for c in &path.0 {
        write_u16(out, u16_checked(c.len(), "path component length")?)?;
        out.write_all(c)?;
    }
    Ok(())
}

fn write_meta(out: &mut dyn Write, meta: Meta) -> Result<()> {
    write_u32(out, meta.mode)?;
    write_u32(out, meta.uid)?;
    write_u32(out, meta.gid)?;
    write_u64(out, meta.mtime_ns)?;
    Ok(())
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    push_u32(out, u32_checked(bytes.len(), "byte string length")?);
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_vec_bytes(out: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<()> {
    push_u32(out, u32_checked(values.len(), "bytes vector length")?);
    for value in values {
        push_bytes(out, value)?;
    }
    Ok(())
}

fn push_path(out: &mut Vec<u8>, path: &PathParts) -> Result<()> {
    path.validate()?;
    push_u16(out, u16_checked(path.0.len(), "path component count")?);
    for c in &path.0 {
        push_u16(out, u16_checked(c.len(), "path component length")?);
        out.extend_from_slice(c);
    }
    Ok(())
}

fn chunk_key(id: &[u8; 32]) -> String {
    let h = hex(id);
    format!("chunks/{}/{}.age", &h[..2], h)
}

fn manifest_key(snapshot_id: &[u8; 32]) -> String {
    let h = hex(snapshot_id);
    format!("manifests/{}/{}.manifest.age", &h[..2], h)
}

fn commit_key(created_unix_ns: u64, snapshot_id: &[u8; 32]) -> String {
    format!("commits/{}-{}.commit", created_unix_ns, hex(snapshot_id))
}

fn fill_random(bytes: &mut [u8]) -> Result<()> {
    fill_random_bytes(bytes).map_err(|e| format!("getrandom failed: {e}").into())
}

fn unix_nanos() -> Result<u64> {
    let d = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(d.as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(d.subsec_nanos() as u64))
}

fn parse_s3_last_modified_unix_ns(value: &str) -> Result<u64> {
    let value = value
        .strip_suffix('Z')
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?;
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts
        .next()
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?
        .parse()?;
    let month: u32 = date_parts
        .next()
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?
        .parse()?;
    let day: u32 = date_parts
        .next()
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?
        .parse()?;
    if date_parts.next().is_some() {
        return err(format!("invalid S3 LastModified timestamp: {value}"));
    }
    let mut time_parts = time.split(':');
    let hour: u32 = time_parts
        .next()
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?
        .parse()?;
    let minute: u32 = time_parts
        .next()
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?
        .parse()?;
    let second_text = time_parts
        .next()
        .ok_or_else(|| format!("invalid S3 LastModified timestamp: {value}"))?;
    if time_parts.next().is_some() {
        return err(format!("invalid S3 LastModified timestamp: {value}"));
    }
    let (second_text, frac_text) = second_text.split_once('.').unwrap_or((second_text, ""));
    let second: u32 = second_text.parse()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return err(format!("invalid S3 LastModified timestamp: {value}"));
    }
    let mut nanos = 0u32;
    if !frac_text.is_empty() {
        let digits = frac_text.as_bytes();
        if !digits.iter().all(u8::is_ascii_digit) {
            return err(format!("invalid S3 LastModified timestamp: {value}"));
        }
        let take = digits.len().min(9);
        let mut parsed = 0u32;
        for b in &digits[..take] {
            parsed = parsed
                .checked_mul(10)
                .and_then(|v| v.checked_add(u32::from(b - b'0')))
                .ok_or_else(|| "timestamp nanosecond overflow".to_string())?;
        }
        for _ in take..9 {
            parsed *= 10;
        }
        nanos = parsed;
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return err("S3 LastModified is before Unix epoch");
    }
    let secs = (days as u64)
        .saturating_mul(24 * 60 * 60)
        .saturating_add(u64::from(hour) * 60 * 60)
        .saturating_add(u64::from(minute) * 60)
        .saturating_add(u64::from(second));
    Ok(secs
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(nanos)))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn read_to_string(path: &Path) -> Result<String> {
    let mut s = String::new();
    File::open(path)?.read_to_string(&mut s)?;
    Ok(s)
}

fn write_private_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).mode(0o600);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_public_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).mode(0o644);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

struct PreparedPrivateFile {
    final_path: PathBuf,
    temp_path: PathBuf,
    overwrite: bool,
}

impl PreparedPrivateFile {
    fn create(path: &Path, bytes: &[u8], overwrite: bool) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    return err(format!(
                        "private file path is a directory: {}",
                        path.display()
                    ));
                }
                if !overwrite {
                    return err(format!("private file already exists: {}", path.display()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| "private file path has no file name".to_string())?
            .as_bytes();
        let mut temp_path = None;
        for _ in 0..100 {
            let mut random = [0u8; 16];
            fill_random(&mut random)?;
            let mut temp_name = Vec::new();
            temp_name.extend_from_slice(b".agesnap-prepared-");
            temp_name.extend_from_slice(name);
            temp_name.push(b'-');
            temp_name.extend_from_slice(hex(&random).as_bytes());
            let candidate = parent.join(OsStr::from_bytes(&temp_name));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&candidate)
            {
                Ok(mut file) => {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o600))?;
                    temp_path = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Self {
            final_path: path.to_path_buf(),
            temp_path: temp_path
                .ok_or_else(|| "could not reserve private file path".to_string())?,
            overwrite,
        })
    }

    fn commit(&self) -> Result<()> {
        if self.overwrite {
            fs::rename(&self.temp_path, &self.final_path)?;
        } else {
            fs::hard_link(&self.temp_path, &self.final_path)?;
            fs::remove_file(&self.temp_path)?;
        }
        fs::set_permissions(&self.final_path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn discard(&self) {
        let _ = fs::remove_file(&self.temp_path);
    }
}

struct PreparedPublicFile {
    final_path: PathBuf,
    temp_path: PathBuf,
    overwrite: bool,
}

impl PreparedPublicFile {
    fn create(path: &Path, bytes: &[u8], overwrite: bool) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    return err(format!(
                        "public file path is a directory: {}",
                        path.display()
                    ));
                }
                if !overwrite {
                    return err(format!("public file already exists: {}", path.display()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| "public file path has no file name".to_string())?
            .as_bytes();
        let mut temp_path = None;
        for _ in 0..100 {
            let mut random = [0u8; 16];
            fill_random(&mut random)?;
            let mut temp_name = Vec::new();
            temp_name.extend_from_slice(b".agesnap-prepared-");
            temp_name.extend_from_slice(name);
            temp_name.push(b'-');
            temp_name.extend_from_slice(hex(&random).as_bytes());
            let candidate = parent.join(OsStr::from_bytes(&temp_name));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&candidate)
            {
                Ok(mut file) => {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o644))?;
                    temp_path = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Self {
            final_path: path.to_path_buf(),
            temp_path: temp_path.ok_or_else(|| "could not reserve public file path".to_string())?,
            overwrite,
        })
    }

    fn commit(&self) -> Result<()> {
        if self.overwrite {
            fs::rename(&self.temp_path, &self.final_path)?;
        } else {
            fs::hard_link(&self.temp_path, &self.final_path)?;
            fs::remove_file(&self.temp_path)?;
        }
        fs::set_permissions(&self.final_path, fs::Permissions::from_mode(0o644))?;
        Ok(())
    }

    fn discard(&self) {
        let _ = fs::remove_file(&self.temp_path);
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex(s)?;
    if bytes.len() != 32 {
        return err("expected 32-byte hex value");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return err("hex string has odd length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = hex_val(b[i])?;
        let lo = hex_val(b[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => err("invalid hex digit"),
    }
}

fn u16_checked(value: usize, label: &str) -> Result<u16> {
    u16::try_from(value).map_err(|_| format!("{label} exceeds u16").into())
}

fn u32_checked(value: usize, label: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| format!("{label} exceeds u32").into())
}

fn usize_checked_u64(value: u64, label: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| format!("{label} exceeds usize").into())
}

fn os_string_to_string(value: OsString, label: &str) -> Result<String> {
    value
        .into_string()
        .map_err(|_| format!("{label} must be valid UTF-8").into())
}

fn path_to_config_value(path: &Path) -> Result<String> {
    path.as_os_str()
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "config paths must be valid UTF-8".into())
}

fn resolve_config_path(config_path: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(path)
}

fn absolutize_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => err(format!("invalid boolean value: {value}")),
    }
}

fn parse_duration_secs(value: &str) -> Result<u64> {
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'0'..=b'9') => (value, 1),
        _ => return err(format!("invalid duration: {value}")),
    };
    if number.is_empty() {
        return err(format!("invalid duration: {value}"));
    }
    Ok(number.parse::<u64>()?.saturating_mul(multiplier))
}

fn format_duration_secs(seconds: u64) -> String {
    if seconds.is_multiple_of(24 * 60 * 60) {
        format!("{}d", seconds / (24 * 60 * 60))
    } else if seconds.is_multiple_of(60 * 60) {
        format!("{}h", seconds / (60 * 60))
    } else if seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn parse_compression_level(value: &str) -> Result<i32> {
    let level: i32 = value.parse()?;
    if !(0..=19).contains(&level) {
        return err("compression level must be between 0 and 19");
    }
    Ok(level)
}

fn validate_chunk_settings(min: u32, target: u32, max: u32) -> Result<()> {
    if min < 256 * 1024 {
        return err("chunk.min must be at least 256 KiB");
    }
    if target < min.saturating_mul(2) {
        return err("chunk.avg must be at least 2 * chunk.min");
    }
    if max < target.saturating_mul(2) {
        return err("chunk.max must be at least 2 * chunk.avg");
    }
    if max > 64 * 1024 * 1024 {
        return err("chunk.max must be at most 64 MiB");
    }
    Ok(())
}

fn load_local_config_arg(p: &mut ArgParser) -> Result<Option<LoadedLocalConfig>> {
    let Some(path) = p.value_path("--config") else {
        return Ok(None);
    };
    let config = LocalConfig::read(&path)?;
    Ok(Some(LoadedLocalConfig { path, config }))
}

fn repo_from_args_or_config(
    p: &mut ArgParser,
    loaded_config: Option<&LoadedLocalConfig>,
) -> Result<S3Repo> {
    if let Some(repo) = p.value("--repo")? {
        return S3Repo::parse(&repo);
    }
    loaded_config
        .map(|loaded| loaded.config.repo.clone())
        .ok_or_else(|| "missing --repo or --config".into())
}

fn capability_path_from_args_or_config(
    p: &mut ArgParser,
    loaded_config: Option<&LoadedLocalConfig>,
) -> Result<PathBuf> {
    if let Some(path) = p.value_path("--capability") {
        return Ok(path);
    }
    loaded_config
        .and_then(LoadedLocalConfig::capability_path)
        .ok_or_else(|| "missing --capability or config capability".into())
}

fn apply_s3_args(p: &mut ArgParser, options: &mut S3ClientOptions) -> Result<()> {
    if let Some(region) = p.value("--s3-region")? {
        options.region = Some(region);
    }
    if let Some(endpoint) = p.value("--s3-endpoint")? {
        options.endpoint = Some(endpoint);
    }
    if p.flag("--s3-path-style") {
        options.path_style = true;
    }
    if p.flag("--no-s3-path-style") {
        options.path_style = false;
    }
    Ok(())
}

struct ArgParser {
    args: Vec<OsString>,
    used: Vec<bool>,
}

impl ArgParser {
    fn new(args: Vec<OsString>) -> Self {
        let used = vec![false; args.len()];
        Self { args, used }
    }

    fn flag(&mut self, name: &str) -> bool {
        for i in 0..self.args.len() {
            if !self.used[i] && self.args[i] == OsStr::new(name) {
                self.used[i] = true;
                return true;
            }
        }
        false
    }

    fn value_os(&mut self, name: &str) -> Option<OsString> {
        for i in 0..self.args.len() {
            if !self.used[i] && self.args[i] == OsStr::new(name) {
                self.used[i] = true;
                if i + 1 >= self.args.len() || self.args[i + 1].as_bytes().starts_with(b"--") {
                    return None;
                }
                self.used[i + 1] = true;
                return Some(self.args[i + 1].clone());
            }
        }
        None
    }

    fn value_path(&mut self, name: &str) -> Option<PathBuf> {
        self.value_os(name).map(PathBuf::from)
    }

    fn value(&mut self, name: &str) -> Result<Option<String>> {
        self.value_os(name)
            .map(|value| os_string_to_string(value, name))
            .transpose()
    }

    fn required_value(&mut self, name: &str) -> Result<String> {
        self.value(name)?
            .ok_or_else(|| format!("missing {name}").into())
    }

    fn required_path(&mut self, name: &str) -> Result<PathBuf> {
        self.value_path(name)
            .ok_or_else(|| format!("missing {name}").into())
    }

    fn values(&mut self, name: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        while let Some(value) = self.value_os(name) {
            out.push(os_string_to_string(value, name)?);
        }
        Ok(out)
    }

    fn values_os(&mut self, name: &str) -> Vec<OsString> {
        let mut out = Vec::new();
        while let Some(value) = self.value_os(name) {
            out.push(value);
        }
        out
    }

    fn rest_paths(&mut self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for i in 0..self.args.len() {
            if !self.used[i] && !self.args[i].as_bytes().starts_with(b"--") {
                self.used[i] = true;
                out.push(PathBuf::from(self.args[i].clone()));
            }
        }
        out
    }

    fn finish(&self) -> Result<()> {
        for (arg, used) in self.args.iter().zip(&self.used) {
            if !used {
                return err(format!("unexpected argument: {}", arg.to_string_lossy()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "agesnap-test-{name}-{}-{}",
                std::process::id(),
                unix_nanos()?
            ));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_meta() -> Meta {
        Meta {
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
        }
    }

    fn valid_asar(repo_id: &[u8; 32]) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        write_asar_header(&mut bytes, repo_id)?;
        write_dir_record(&mut bytes, &PathParts(vec![b"root".to_vec()]), test_meta())?;
        bytes.push(REC_END);
        Ok(bytes)
    }

    fn assert_no_restore_temps(dir: &Path) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            assert!(!entry.file_name().as_bytes().starts_with(b".agesnap-tmp-"));
        }
        Ok(())
    }

    #[test]
    fn chunk_verification_rejects_valid_wrong_chunk() -> Result<()> {
        let repo_id = [2u8; 32];
        let key = [7u8; 32];
        let expected_id = chunk_id(&key, b"expected");
        let plaintext = encode_chunk_plaintext(&repo_id, &expected_id, b"replaced", 0)?;

        let error = decode_chunk_plaintext(&repo_id, &key, &expected_id, &plaintext)
            .expect_err("wrong plaintext must fail keyed verification");
        assert!(error.to_string().contains("keyed chunk verification"));
        Ok(())
    }

    #[test]
    fn tampered_chunk_plaintext_is_rejected() -> Result<()> {
        let repo_id = [3u8; 32];
        let key = [9u8; 32];
        let chunk = b"hello chunk";
        let id = chunk_id(&key, chunk);
        let mut plaintext = encode_chunk_plaintext(&repo_id, &id, chunk, 0)?;
        let last = plaintext.last_mut().expect("encoded chunk is non-empty");
        *last ^= 1;

        assert!(decode_chunk_plaintext(&repo_id, &key, &id, &plaintext).is_err());
        Ok(())
    }

    #[test]
    fn commit_mac_rejects_tampering() -> Result<()> {
        let key = [4u8; 32];
        let commit = Commit {
            repo_id: [1u8; 32],
            snapshot_id: [2u8; 32],
            manifest_key: manifest_key(&[2u8; 32]),
            created_unix_ns: 10,
            parent_snapshot_id: None,
            mac: [0u8; 32],
        };
        let text = commit.encode_signed(&key);
        Commit::verify_text(&text, &key)?;

        let tampered = text.replace("created_unix_ns=10", "created_unix_ns=11");
        assert!(Commit::verify_text(&tampered, &key).is_err());
        Ok(())
    }

    #[test]
    fn asar_validator_accepts_valid_stream_in_pieces() -> Result<()> {
        let repo_id = [5u8; 32];
        let bytes = valid_asar(&repo_id)?;
        let mut validator = AsarStreamValidator::new(repo_id);
        for chunk in bytes.chunks(3) {
            validator.push(chunk)?;
        }
        validator.finish()
    }

    #[test]
    fn asar_validator_requires_end_record() -> Result<()> {
        let repo_id = [6u8; 32];
        let mut bytes = Vec::new();
        write_asar_header(&mut bytes, &repo_id)?;
        let mut validator = AsarStreamValidator::new(repo_id);
        validator.push(&bytes)?;

        let error = validator
            .finish()
            .expect_err("validator must require an end record");
        assert!(error.to_string().contains("missing ASAR end"));
        Ok(())
    }

    #[test]
    fn asar_validator_rejects_repo_mismatch() -> Result<()> {
        let bytes = valid_asar(&[7u8; 32])?;
        let mut validator = AsarStreamValidator::new([8u8; 32]);
        let error = validator
            .push(&bytes)
            .expect_err("repo mismatch must be rejected");
        assert!(error.to_string().contains("repo id mismatch"));
        Ok(())
    }

    #[test]
    fn restore_path_parser_rejects_unsafe_components() {
        let path = OsString::from_vec(b"root/../etc".to_vec());
        assert!(parse_restore_path_arg(&path).is_err());
    }

    #[test]
    fn restore_path_parser_preserves_non_utf8_components() -> Result<()> {
        let path = OsString::from_vec(vec![0xff, b'/', b'a']);
        let parsed = parse_restore_path_arg(&path)?;
        assert_eq!(parsed.0, vec![vec![0xff], vec![b'a']]);
        Ok(())
    }

    #[test]
    fn public_config_uses_repo_spec_format() -> Result<()> {
        let config = PublicConfig {
            repo_id: [1u8; 32],
            created_unix_ns: 99,
            min_chunk: DEFAULT_MIN_CHUNK,
            target_chunk: DEFAULT_TARGET_CHUNK,
            max_chunk: DEFAULT_MAX_CHUNK,
        };
        let text = config.encode();
        assert!(text.starts_with("agesnap-repo-v1\n"));
        assert!(text.contains("chunker=gear\n"));
        assert!(text.contains("archive_format=asar-v1\n"));
        assert!(!text.contains("recipient="));
        let parsed = PublicConfig::parse(&text)?;
        assert_eq!(parsed.repo_id, config.repo_id);
        assert_eq!(parsed.created_unix_ns, 99);
        Ok(())
    }

    #[test]
    fn local_config_round_trips_s3_and_policy_fields() -> Result<()> {
        let mut config = LocalConfig::default_for_repo(S3Repo::parse("s3://bucket/prefix")?);
        config.capability = Some(PathBuf::from("/tmp/backup.cap"));
        config.s3.region = Some("us-west-2".to_string());
        config.s3.endpoint = Some("https://s3.example.test".to_string());
        config.s3.path_style = true;
        config.metadata_policy = MetadataPolicy::BestEffort;
        config.compression_level = 0;
        config.gc_min_age_secs = 2 * 24 * 60 * 60;

        let text = config.encode()?;
        assert!(text.starts_with("agesnap-config-v1\n"));
        assert!(text.contains("repo.url=s3://bucket/prefix\n"));
        assert!(text.contains("capability.file=/tmp/backup.cap\n"));
        assert!(!text.contains("s3.bucket="));
        assert!(text.contains("gc.min_age=2d\n"));
        let parsed = LocalConfig::parse(&text)?;
        assert_eq!(parsed.repo, config.repo);
        assert_eq!(parsed.capability, config.capability);
        assert_eq!(parsed.s3.region, config.s3.region);
        assert_eq!(parsed.s3.endpoint, config.s3.endpoint);
        assert!(parsed.s3.path_style);
        assert_eq!(parsed.metadata_policy, MetadataPolicy::BestEffort);
        assert_eq!(parsed.compression_level, 0);
        assert_eq!(parsed.gc_min_age_secs, 2 * 24 * 60 * 60);
        Ok(())
    }

    #[test]
    fn local_config_accepts_spaced_keys_and_rejects_unknowns() -> Result<()> {
        let text = "\
agesnap-config-v1
repo.url = s3://bucket/prefix
capability.file = ./backup.cap
s3.region = eu-central-1
s3.endpoint = https://s3.example.test
s3.path_style = true
metadata.policy = strict
compression.level = 3
chunk.min = 1048576
chunk.avg = 4194304
chunk.max = 16777216
gc.min_age = 7d
";
        let parsed = LocalConfig::parse(text)?;
        assert_eq!(parsed.repo, S3Repo::parse("s3://bucket/prefix")?);
        assert_eq!(parsed.capability, Some(PathBuf::from("./backup.cap")));

        let duplicate = text.replace("gc.min_age = 7d", "gc.min_age = 7d\ngc.min_age = 8d");
        assert!(LocalConfig::parse(&duplicate).is_err());

        let unknown = text.replace("gc.min_age = 7d", "gc.min_age = 7d\nsurprise = no");
        assert!(LocalConfig::parse(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn local_config_allows_leading_blank_and_comment_lines() -> Result<()> {
        let text = "
# created by hand
agesnap-config-v1
repo.url = s3://bucket/prefix
";
        let parsed = LocalConfig::parse(text)?;
        assert_eq!(parsed.repo, S3Repo::parse("s3://bucket/prefix")?);
        Ok(())
    }

    #[test]
    fn s3_repo_rejects_prefix_that_can_exceed_key_limit() -> Result<()> {
        let max_prefix = S3_MAX_OBJECT_KEY_BYTES - 1 - MAX_GENERATED_S3_KEY_BYTES;
        let ok = format!("s3://bucket/{}", "a".repeat(max_prefix));
        assert!(S3Repo::parse(&ok).is_ok());

        let too_long = format!("s3://bucket/{}", "a".repeat(max_prefix + 1));
        assert!(S3Repo::parse(&too_long).is_err());
        Ok(())
    }

    #[test]
    fn manifest_encode_rejects_values_parser_would_reject() {
        let mut manifest = SnapshotManifest {
            repo_id: [1u8; 32],
            created_unix_ns: 1,
            archive_len: 0,
            name: Vec::new(),
            tags: Vec::new(),
            roots: vec![PathParts(vec![b"root".to_vec()])],
            files: 0,
            directories: 1,
            symlinks: 0,
            hardlinks: 0,
            logical_bytes: 0,
            chunk_refs: vec![ChunkRef {
                id: [2u8; 32],
                plaintext_len: 0,
            }],
        };

        manifest.name = vec![b'n'; MAX_MANIFEST_TEXT_BYTES + 1];
        assert!(manifest.encode().is_err());

        manifest.name.clear();
        manifest.tags = vec![vec![b't'; MAX_MANIFEST_TEXT_BYTES + 1]];
        assert!(manifest.encode().is_err());

        manifest.tags.clear();
        manifest.chunk_refs[0].plaintext_len = (MAX_CHUNK_PLAINTEXT_BYTES as u32) + 1;
        assert!(manifest.encode().is_err());
    }

    #[test]
    fn commit_parser_rejects_mismatched_manifest_path() {
        let text = "\
agesnap-commit-v1
repo_id=0101010101010101010101010101010101010101010101010101010101010101
snapshot_id=0202020202020202020202020202020202020202020202020202020202020202
manifest=secrets.age
created_unix_ns=10
parent_snapshot_id=
mac=0303030303030303030303030303030303030303030303030303030303030303
";
        assert!(Commit::parse_unverified(text).is_err());
    }

    #[test]
    fn chunk_settings_enforce_no_multipart_bounds() {
        assert!(
            validate_chunk_settings(255 * 1024, DEFAULT_TARGET_CHUNK, DEFAULT_MAX_CHUNK).is_err()
        );
        assert!(validate_chunk_settings(1024 * 1024, 1024 * 1024, DEFAULT_MAX_CHUNK).is_err());
        assert!(validate_chunk_settings(1024 * 1024, 2 * 1024 * 1024, 3 * 1024 * 1024).is_err());
        assert!(validate_chunk_settings(1024 * 1024, 4 * 1024 * 1024, 65 * 1024 * 1024).is_err());
        assert!(
            validate_chunk_settings(DEFAULT_MIN_CHUNK, DEFAULT_TARGET_CHUNK, DEFAULT_MAX_CHUNK)
                .is_ok()
        );
    }

    #[test]
    fn binary_limits_reject_oversized_path_component() {
        let component = vec![b'a'; MAX_PATH_COMPONENT_BYTES + 1];
        assert!(validate_component(&component).is_err());
    }

    #[test]
    fn chunk_decoder_rejects_oversized_declared_plaintext() -> Result<()> {
        let repo_id = [1u8; 32];
        let key = [2u8; 32];
        let expected_id = [3u8; 32];
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(CHUNK_MAGIC);
        push_u16(&mut plaintext, 1);
        push_u16(&mut plaintext, 0);
        plaintext.extend_from_slice(&repo_id);
        plaintext.extend_from_slice(&expected_id);
        push_u32(&mut plaintext, (MAX_CHUNK_PLAINTEXT_BYTES as u32) + 1);
        plaintext.push(0);
        plaintext.extend_from_slice(&[0, 0, 0]);
        push_bytes(&mut plaintext, b"")?;

        assert!(decode_chunk_plaintext(&repo_id, &key, &expected_id, &plaintext).is_err());
        Ok(())
    }

    #[test]
    fn list_objects_xml_parser_decodes_required_fields() -> Result<()> {
        let xml = r#"
            <ListBucketResult>
                <IsTruncated>true</IsTruncated>
                <EncodingType>url</EncodingType>
                <Contents>
                    <Key>chunks/ab/a%26%7B%7Db.age</Key>
                    <LastModified>2026-04-27T09:08:07.123456789Z</LastModified>
                </Contents>
                <NextContinuationToken>next&lt;&#116;oken&gt;</NextContinuationToken>
            </ListBucketResult>
        "#;
        let page = parse_list_objects_v2_xml(xml)?;
        assert!(page.is_truncated);
        assert_eq!(page.next_continuation_token.as_deref(), Some("next<token>"));
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "chunks/ab/a&{}b.age");
        assert_eq!(
            page.objects[0].last_modified_unix_ns,
            Some(parse_s3_last_modified_unix_ns(
                "2026-04-27T09:08:07.123456789Z"
            )?)
        );
        Ok(())
    }

    #[test]
    fn list_objects_xml_parser_leaves_percent_without_encoding_type() -> Result<()> {
        let xml = r#"
            <ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <Contents>
                    <Key>chunks/ab/a%2Fb.age</Key>
                </Contents>
            </ListBucketResult>
        "#;
        let page = parse_list_objects_v2_xml(xml)?;
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "chunks/ab/a%2Fb.age");
        Ok(())
    }

    #[test]
    fn overwrite_file_restore_keeps_existing_until_temp_is_complete() -> Result<()> {
        let dir = TestDir::new("overwrite")?;
        let final_path = dir.path.join("file");
        fs::write(&final_path, b"old")?;
        let root = RestoreRoot::prepare(dir.path.clone())?;
        let md = fs::metadata(&final_path)?;
        let meta = Meta::from_metadata(&md);

        let mut restore = start_file_restore(
            &root,
            PathParts(vec![b"file".to_vec()]),
            meta,
            3,
            true,
            MetadataPolicy::Strict,
        )?;
        assert_eq!(fs::read(&final_path)?, b"old");

        restore.file.write_all(b"new")?;
        restore.remaining = 0;
        finish_file_restore(restore)?;
        assert_eq!(fs::read(&final_path)?, b"new");
        Ok(())
    }

    #[test]
    fn restore_file_removes_temp_when_final_link_fails() -> Result<()> {
        let dir = TestDir::new("restore-temp-cleanup")?;
        let final_path = dir.path.join("file");
        let root = RestoreRoot::prepare(dir.path.clone())?;
        let meta = Meta {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        };

        let mut restore = start_file_restore(
            &root,
            PathParts(vec![b"file".to_vec()]),
            meta,
            3,
            false,
            MetadataPolicy::BestEffort,
        )?;
        let temp_path = dir
            .path
            .join(OsStr::from_bytes(restore.temp_name.as_bytes()));
        restore.file.write_all(b"new")?;
        restore.remaining = 0;
        fs::write(&final_path, b"old")?;

        assert!(finish_file_restore(restore).is_err());
        assert_eq!(fs::read(&final_path)?, b"old");
        assert!(!temp_path.exists());
        Ok(())
    }

    #[test]
    fn overwrite_symlink_restore_keeps_existing_when_temp_creation_fails() -> Result<()> {
        let dir = TestDir::new("symlink-overwrite-failure")?;
        let final_path = dir.path.join("link");
        fs::write(&final_path, b"old")?;
        let root = RestoreRoot::prepare(dir.path.clone())?;
        let too_long_target = vec![b'a'; MAX_SYMLINK_TARGET_BYTES];

        assert!(
            restore_symlink(
                &root,
                &PathParts(vec![b"link".to_vec()]),
                &too_long_target,
                test_meta(),
                true,
                MetadataPolicy::Strict,
            )
            .is_err()
        );
        assert_eq!(fs::read(&final_path)?, b"old");
        assert_no_restore_temps(&dir.path)
    }

    #[test]
    fn overwrite_hardlink_restore_keeps_existing_when_link_fails() -> Result<()> {
        let dir = TestDir::new("hardlink-overwrite-failure")?;
        fs::create_dir(dir.path.join("target-dir"))?;
        let final_path = dir.path.join("file");
        fs::write(&final_path, b"old")?;
        let root = RestoreRoot::prepare(dir.path.clone())?;

        let restored = restore_hardlink(
            &root,
            &PathParts(vec![b"file".to_vec()]),
            &PathParts(vec![b"target-dir".to_vec()]),
            test_meta(),
            true,
            MetadataPolicy::BestEffort,
        )?;
        assert!(!restored);
        assert_eq!(fs::read(&final_path)?, b"old");
        assert_no_restore_temps(&dir.path)
    }

    #[test]
    fn backup_directory_read_stays_on_open_fd_after_path_replacement() -> Result<()> {
        let dir = TestDir::new("backup-dir-race")?;
        let source = dir.path.join("source");
        let moved = dir.path.join("moved");
        let outside = dir.path.join("outside");
        fs::create_dir(&source)?;
        fs::create_dir(&outside)?;
        fs::write(source.join("kept"), b"kept")?;
        fs::write(outside.join("leaked"), b"leaked")?;

        let meta = fs::symlink_metadata(&source)?;
        let opened = open_backup_dir(&source, &meta)?;
        fs::rename(&source, &moved)?;
        std::os::unix::fs::symlink(&outside, &source)?;

        assert_eq!(read_dir_names_fd(&opened)?, vec![b"kept".to_vec()]);
        Ok(())
    }

    #[test]
    fn duration_parser_accepts_gc_units() -> Result<()> {
        assert_eq!(parse_duration_secs("7d")?, 7 * 24 * 60 * 60);
        assert_eq!(parse_duration_secs("2h")?, 2 * 60 * 60);
        assert_eq!(parse_duration_secs("30m")?, 30 * 60);
        assert_eq!(parse_duration_secs("15s")?, 15);
        assert_eq!(parse_duration_secs("9")?, 9);
        assert_eq!(format_duration_secs(7 * 24 * 60 * 60), "7d");
        Ok(())
    }

    #[test]
    fn s3_last_modified_parser_handles_epoch_and_fraction() -> Result<()> {
        assert_eq!(parse_s3_last_modified_unix_ns("1970-01-01T00:00:00Z")?, 0);
        assert_eq!(
            parse_s3_last_modified_unix_ns("1970-01-01T00:00:01.5Z")?,
            1_500_000_000
        );
        Ok(())
    }

    #[test]
    fn same_size_file_change_is_not_same_snapshot() -> Result<()> {
        let dir = TestDir::new("mtime")?;
        let path = dir.path.join("file");
        fs::write(&path, b"aa")?;
        let before = fs::metadata(&path)?;
        fs::write(&path, b"bb")?;
        let file = OpenOptions::new().write(true).open(&path)?;
        set_mtime_fd(
            file.as_raw_fd(),
            Meta::from_metadata(&before)
                .mtime_ns
                .saturating_add(1_000_000_000),
        )?;
        let after = fs::metadata(&path)?;

        assert_eq!(before.len(), after.len());
        assert!(!same_file_snapshot(&after, &before));
        Ok(())
    }
}
