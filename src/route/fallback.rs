use anyhow::Context;
use async_recursion::async_recursion;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;
use tokio::fs;

const DEFAULT_404_HTML: &str = "<!doctype html>\
        <html lang=\"en\">\
            <head><meta charset=\"utf-8\"><title>404 Not Found</title></head>\
            <body><h1>404 Not Found</h1><p>The page you requested does not exist.</p></body>\
        </html>";

// Static site: all content is read once at startup and lives in memory
// (the site is small — tens/hundreds of KB), so serving is fast and
// there is no path for directory traversal by construction: the
// HashMap keys are built purely by walking the directory on disk, not
// from a user-supplied Path, so "../../etc/passwd" simply never
// matches any known key.

#[derive(Clone)]
pub struct FileEntry {
    pub bytes: Bytes,
    pub content_type: &'static str,
    pub etag: String,
    pub last_modified: String,
}

pub struct StaticSite {
    files: HashMap<String, FileEntry>,
    not_found: FileEntry,
}

impl StaticSite {
    pub async fn try_load(root: &Path) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        walk_dir(root, root, &mut files).await?;

        if !files.contains_key("/index.html") {
            anyhow::bail!("static_dir ({root:?}) must contain an index.html at its root");
        }

        let not_found = files.get("/404.html").cloned().unwrap_or_else(|| {
            let bytes = Bytes::from_static(DEFAULT_404_HTML.as_bytes());
            FileEntry {
                etag: make_etag(bytes.len() as u64, 0),
                last_modified: httpdate::fmt_http_date(SystemTime::now()),
                content_type: "text/html; charset=utf-8",
                bytes,
            }
        });

        tracing::info!(files = files.len(), root = ?root, "static site loaded into memory");
        Ok(Self { files, not_found })
    }

    pub fn resolve(&self, raw_path: &str) -> Option<&FileEntry> {
        let path = raw_path.split('?').next().unwrap_or("/");
        let key = if path == "/" || path.is_empty() {
            "/index.html"
        } else {
            path
        };
        self.files.get(key)
    }

    pub fn not_found(&self) -> &FileEntry {
        &self.not_found
    }
}

#[async_recursion]
async fn walk_dir(
    root: &Path,
    dir: &Path,
    out: &mut HashMap<String, FileEntry>,
) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(dir)
        .await
        .with_context(|| format!("reading directory {dir:?}"))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_type = entry.file_type().await?;

        if file_type.is_dir() {
            walk_dir(root, &path, out).await?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let url_path = format!("/{}", rel.to_string_lossy().replace('\\', "/"));

            let bytes = fs::read(&path)
                .await
                .with_context(|| format!("reading file {path:?}"))?;

            let meta = fs::metadata(&path).await?;

            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

            let mtime_secs = mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            out.insert(
                url_path,
                FileEntry {
                    content_type: content_type_for(ext),
                    etag: make_etag(bytes.len() as u64, mtime_secs),
                    last_modified: httpdate::fmt_http_date(mtime),
                    bytes: Bytes::from(bytes),
                },
            );
        }
    }
    Ok(())
}

fn content_type_for(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// Formatted like a standard nginx ETag: "<hex mtime>-<hex size>".
fn make_etag(size: u64, mtime_secs: u64) -> String {
    format!("\"{mtime_secs:x}-{size:x}\"")
}
