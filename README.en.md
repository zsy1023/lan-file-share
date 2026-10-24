# LAN HTTPS File Sharing (lan-file-share)

[中文](README.md) | **English**

An **out-of-the-box** Node.js program that shares a folder on your computer over
HTTPS, so phones / tablets / other computers on the same LAN can open a URL in a
browser to browse the directory tree and **download / upload** files.

> Highlights: LAN-only, no internet required. The core is dependency-free — just
> install Node.js and it runs. Three optional dependencies enhance the
> "low-res preview / ZIP packaging / WebDAV mounting" experience (see the table below).
> The server listens on **IPv4 + IPv6 (dual stack)** by default — falling back to
> IPv4-only when the system has IPv6 disabled — and prints every LAN address it has,
> IPv6 included. You can also add a **root access password** to the main share from
> the web UI so LAN devices must authenticate first (see [section 7](#7-root-access-password-optional-lan-only)).

---

## 1. What this is / What you need

| Dependency | Notes |
|------|------|
| Node.js `>=18` | Runs the server itself |
| `sharp` (optional) | Generates low-res image previews. Installed → previews are faster and use less bandwidth; not installed → previews load the original image |
| `ffmpeg` (optional) | Extracts a cover frame for videos. Installed → videos show a cover in the list and can be played inline; not installed → only a 🎬 icon |
| `archiver` (optional) | Packages selections into a ZIP for batch download. Not installed → "Download selected" is unavailable; single-file download is unaffected |
| `webdav-server` (optional) | Additionally exposes the shared folder over WebDAV (mountable as a *network drive*). Currently experimental — Windows client support is incomplete; not installed → web access only |
| OpenSSL | Needed only **once** to generate a self-signed certificate; on Windows you can use the openssl bundled with Git for Windows |

> The project core is dependency-free (Node.js built-in modules only). Every
> dependency below is an **optional enhancement**. For first use it is recommended
> to run `npm install` in this directory; without it everything still runs, only
> the corresponding features are unavailable (previews fall back to the original
> image, batch download is off, WebDAV is disabled).

Project files:

```
lan-file-share/
├─ server.js        # HTTPS server (browse + download + upload + live sync + per-folder share + access password + action log)
├─ gen-cert.js      # Generates the self-signed HTTPS cert (with SANs for every LAN IPv4 / IPv6 address)
├─ gen-csr.js       # For a free CA (Let's Encrypt / ZeroSSL …): generates a new key + CSR
├─ start.bat        # [Recommended] one-click start on Windows (auto-generates the cert if missing)
├─ setup.bat        # [Recommended] one-click setup on Windows (deps + cert + start)
├─ setup.sh         # One-click setup for Linux / macOS (same steps)
├─ config.json      # Config: share folder, port, upload size cap, log level, etc.
├─ shares.json      # Records of individual shares (auto-created after first share; password hashes only)
├─ rootauth.json    # Record of the main share's root access password (created when set in the web UI; scrypt hash only)
├─ package.json     # npm start / npm run cert / npm install dependencies
├─ LICENSE          # Full GPL-3.0 license text
├─ README.md        # Chinese documentation
├─ README.en.md     # English documentation (this file)
├─ node_modules/    # Dependencies (sharp / archiver / webdav-server) — created by npm install
├─ certs/           # Certificate auto-generated on first run (server.crt / server.key)
└─ share/           # Default shared folder (point config.json at any folder you like)
```

---

## 2. Quick start (recommended)

### Option 1 — one-click setup (recommended)

Double-click **`setup.bat`** (Windows) or run **`./setup.sh`** in a terminal
(Linux / macOS). It automatically:

1. Checks that Node.js is installed (and points you to https://nodejs.org/ if not)
2. Installs the optional dependencies `sharp` / `archiver` / `webdav-server` (skipped if present)
3. Generates the self-signed HTTPS certificate (skipped if present)
4. Creates the default `share/` folder if it does not exist
5. Starts the server and prints the access URLs

> Re-running is safe: completed steps are skipped, nothing is installed twice.
> If a dependency fails to install the script **does not abort** — it tells you which
> features are unavailable and the server starts anyway.

### Option 2 — manual

1. Open `config.json` in a **text editor** and change `shareRoot` to the **real
   absolute path** of the folder you want to share, e.g. `D:/SharedFiles`
   (use `/` as the separator; a Windows path like `D:\SharedFiles` is best written
   as `D:/SharedFiles`).
2. Double-click **`start.bat`**.
   - On first run it calls OpenSSL to generate `certs/server.crt` (valid for about
     397 days; just run it again after expiry).
   - If it reports that openssl is missing, install Git for Windows or Win64 OpenSSL
     and retry; alternatively run `npm run cert`.
3. After starting, the window prints the access URLs, e.g.:

   ```
   本机访问  : https://localhost:8443/
   局域网访问: https://192.168.1.100:8443/
   IPv6 访问 : https://[2001:db8:abcd:1234:5a6b:7c8d:9e0f:1a2b]:8443/
   监听方式  : IPv4 + IPv6 双栈  (IPv6 设备的浏览器可直接访问上面列出的 IPv6 地址)
   ```

   (The line labelled "本机访问" is local access, "局域网访问" is LAN access, and
   "IPv6 访问" lists IPv6 addresses — the last line states that both address families
   are being served.)

   - **Both IPv4 and IPv6 addresses are listed.** When the machine has an IPv6 address
     (most home broadband and phone hotspots do), you get `https://[2001:db8:...]:8443/`
     entries next to the `https://192.168.x.x:8443/` ones — use whichever a given device
     can reach. IPv6 addresses must be written **inside square brackets** in a URL.
   - Link-local addresses (`fe80::/10`) need a NIC zone ID (such as `%12`) to be
     reachable, so the URL would not work when pasted — the startup only reports how
     many of them exist instead of listing them.
   - **Nothing breaks on IPv6-less systems**: the server falls back to listening on
     IPv4 only and says so on the "监听方式" line.

4. On a LAN device (which must be on the same LAN as the computer), open
   `https://192.168.1.100:8443/` in a browser.

> If you change `port`, replace `8443` above with your port.
> On a LAN device the browser first warns about the self-signed certificate (see
> section 4); if a **root access password** is set, it also asks for a username /
> password first (username is irrelevant, only the password matters — see section 7).

### Linux / macOS notes

It runs **fully** on Linux (the whole thing is one Node script with no Windows-only
dependency), but a few things differ from Windows:

```bash
git clone https://github.com/zsy1023/lan-file-share.git
cd lan-file-share
./setup.sh          # the executable bit is recorded in the repo; on an older clone use
                    # bash setup.sh  (or chmod +x setup.sh)

# just start the server, skipping the one-click install:
node server.js
```

| Point | Notes |
|---|---|
| **Node version** | **Node 20 / 22 LTS** recommended. Recursive directory watching (live silent sync) on Linux needs Node ≥ 19.1; on Node 18 startup prints "the current filesystem does not support recursive watching" and only writes made by this service sync live — everything else still works |
| **OpenSSL** | `gen-cert.js` uses `openssl req -addext`, so **OpenSSL ≥ 1.1.1** is required (Ubuntu 20.04+ / Debian 11+ / RHEL 8+ ship it; CentOS 7's 1.0.2 fails) |
| **Firewall** | `sudo ufw allow 8443/tcp` (Fedora: `sudo firewall-cmd --add-port=8443/tcp --permanent && sudo firewall-cmd --reload`). **Individual share ports** (starting at 9000 by default) need allowing too |
| **Certificate trust** | See the Linux commands under section 4 "Option B" (`update-ca-certificates` on Debian/Ubuntu, `update-ca-trust` on Fedora/RHEL); Chrome / Firefox may keep their own stores |
| **Low ports** | `port` < 1024 needs root or `setcap`; the default 8443 is unaffected |
| **Running in background** | `setup.sh` runs in the foreground; to keep it running use `nohup node server.js > log.txt 2>&1 &`, `screen` / `tmux`, or write your own systemd unit |
| **Windows-only feature** | The "📂 分享本机其他文件夹…" button in the share panel uses the native Windows folder picker; on Linux it reports a failure and you type the absolute path instead (the feature itself still works) |
| **Filename difference** | Linux allows `\` inside filenames, but the server normalises `\` to `/` as a path separator, so such files may not open in the web UI (very rare) |

---

## 3. How devices on the LAN use it

| Action | How |
|------|------|
| Download | Click a file name to download; for images click the thumbnail to enlarge (**a low-res preview opens instantly, then the full-res original replaces it automatically**); for videos click the cover to play inline |
| **Text preview** | Text files (txt / logs / md / json / code …) have a **"预览"** (preview) button on the right — or click the 📄 icon in the grid views — to read them in the page without downloading; only the first 1 MB is read and UTF-8 / GBK are detected automatically |
| New folder | Toolbar **"＋ New folder"** creates a folder in the current directory (hidden for read-only access) |
| **Batch download** | Every row / tile has a checkbox; tick the ones you want and click **"⬇ Download selected"**: **a single selected file downloads directly (no packaging)**; several items or a folder get packaged into one ZIP. Folders are packaged **recursively** (including all nested files). The download shows **real progress** (transferred / total / percent) and **supports resume** (interrupted transfers continue) |
| View | The top toolbar switches between "list / icons / tiles / thumbnails" and a slider adjusts icon size; the choice is remembered |
| Upload files | Click "Choose files to upload" at the top **or drag files onto the page**; multiple selection is supported and same-named files are overwritten. **Large files are transferred in chunks with resume and automatic retry** (see below) |
| Upload folder | Click "📂 Upload folder" at the top and pick a whole folder; the program recreates the original directory structure (empty subfolders are not created) |
| Rename | Click "Rename" on the right of a row and enter a new name |
| Delete | Click the red "Delete" on the right of a row; files are deleted immediately and folders are deleted with all their contents. A confirmation dialog appears first — once confirmed it is **permanent, bypasses the Recycle Bin, and cannot be undone** |
| Enter a subfolder | Click a folder row to enter it; the breadcrumb at the top takes you back up quickly |
| Resume | Downloads support Range, so browser resume works after an interruption |
| **Live sync** | When the top-right shows "synced": no matter **who** changes the shared folder (someone uploading / deleting / renaming, or you editing files directly in Explorer), every open page **silently refreshes the list without a manual reload**. Rows that just changed briefly highlight |
| **Share an individual folder** | Click "Share" on the right of a folder row to expose it on **its own port** (fully identical to the main page: browse / upload / download / delete / rename / preview / live sync). Only the **local** web UI can create or cancel it |

> Note: this version adds **delete / rename / upload-folder** capabilities, unlike
> earlier "browse/download/upload only" releases — so any device that can reach the
> URL can modify and **permanently delete** content in the shared folder (a browser
> confirmation appears first). Only expose it on a **trusted LAN**, and be careful:
> ideally share a dedicated folder rather than scattering all your personal folders.
> If you don't want every device on the LAN to have direct read/write access, set a
> **root access password** from the local web UI (section 7); individual shares can
> have their own passwords too.

---

## 4. HTTPS certificate trust notice (important)

A self-signed certificate is **not issued by an authority**, so the browser shows
"your connection is not private / certificate not trusted" on first visit. This is
**normal** for self-signed certificates; you have two options:

### Option A — quickest: bypass temporarily (recommended for a first try)

In Edge / Chrome: open the https URL → a warning page appears → click "Advanced" →
"Continue to xxx (unsafe)". You may have to click it again on later visits
(Chrome/Edge occasionally require this again after a device reboot).

### Option B — permanent: install the certificate into the trust store (recommended for real use)

Copy `certs/server.crt` from the computer to each device and install it as a
"trusted root certificate"; the browser then stops warning.

- **Windows**: double-click `server.crt` → "Install Certificate" → "Local Machine" →
  "Place all certificates in the following store" → choose "Trusted Root
  Certification Authorities" → finish.
- **Android**: Settings → Security → Encryption & credentials → Install certificate →
  select `server.crt` (transfer the file to the device first); some systems call it
  "Install CA certificate from storage".
- **iPhone/iPad**: transfer `server.crt` to the device (mail / browser / cable) →
  install the profile → then enable **full trust** under
  "Settings - General - About - Certificate Trust Settings".
- **macOS**: double-click `server.crt` → Keychain Access → mark the certificate as
  "Always Trust".
- **Linux** (install into the system trust store):
  ```bash
  # Debian / Ubuntu
  sudo cp certs/server.crt /usr/local/share/ca-certificates/lan-file-share.crt
  sudo update-ca-certificates

  # Fedora / RHEL / CentOS
  sudo cp certs/server.crt /etc/pki/ca-trust/source/anchors/lan-file-share.crt
  sudo update-ca-trust
  ```
  Browsers may keep their own store: Firefox needs the certificate imported once via
  "Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import".

> Note: the certificate automatically includes the machine's LAN **IPv4 and IPv6**
> addresses plus `localhost` (NICs are scanned in real time during generation), so you
> normally don't need to edit anything. If you later change subnets, delete `certs/*`
> and run `node gen-cert.js` again or rerun `start.bat` / `setup.sh`.

### Option C — use a free CA when you own a domain (optional)

If you have a domain (or a free DDNS name) you can switch to a free CA such as
Let's Encrypt / ZeroSSL / FreeSSL; the upside is that **no device has to install
anything** (public CAs are already trusted). Three preconditions:

1. **Free CAs only sign domains, not private IPs** — the certificate contains just the
   name you validated;
2. **Validation has to be DNS-01** — when the name points at a private address the CA
   cannot reach your machine, so you must add a `_acme-challenge.<domain>` **TXT** record;
3. **Clients must browse by name**, and that name has to resolve to the server's LAN IP
   (hosts file / router DNS rewrite / local DNS), otherwise browsers still validate
   against the IP and report a name mismatch.

Flow:

```bash
node gen-csr.js files.example.com      # writes certs/files.example.com.key and .csr
                                       # (never touches your working server.key)
# paste the .csr into the CA's form → do the DNS-01 step → download the signed cert
```

After you get it:

1. save the returned certificate as `certs/server.crt` (append the intermediate chain to
   the same file if the CA provides one);
2. switch to the new key: rename `certs/files.example.com.key` to `server.key`, or point
   `config.json`'s `keyFile` at it;
3. restart the server.

> **Renewal**: free certificates last 90 days. With a DNS API you can automate it with
> `acme.sh --dns` and write the renewed cert to `certs/server.crt` before restarting;
> without automation it is a manual 90-day chore. For pure LAN use, option B
> (self-signed + trust store) is less work — install once, good for two years.

---

## 5. Configuration (config.json)

| Field | Default | Notes |
|------|------|------|
| `shareRoot` | `share` in this directory | Absolute path of the folder to share |
| `port` | `8443` | Listening port of the main share. A high port needs no admin rights; remember to allow it through the Windows firewall |
| `certFile` / `keyFile` | `certs/server.crt` / `certs/server.key` | Certificate / key paths relative to this directory |
| `maxUploadMB` | `0` | Per-file upload cap (MB). `0` means unlimited |
| `allowOverwrite` | `true` | Whether same-named files may be overwritten on upload. `false` returns a conflict |
| `logLevel` | `normal` | Action-log verbosity, see the table below |
| `sharePortBase` | `9000` | When sharing a folder, ports are auto-allocated upward from this value until a free one is found |
| `title` | 局域网文件共享 | Page title and top heading |

> The **root access password** is **not** a `config.json` field: it is a runtime
> setting. Open the web UI **on the local machine** and click "🔒 访问密码" in the
> top-right to enable / change / remove it — it takes effect immediately and is
> recorded in `rootauth.json` next to the program (see section 7).

### Action-log verbosity (`logLevel`)

Logs are printed to the **startup window** (with colors) and can also be viewed in
the web UI via "📋 Action log" in the top-right, which shows the latest 300 entries.
Each line looks like:

```
[2026-10-01 13:31:32] [WRITE] 上传文件 成功 谁: 192.168.1.23(DESKTOP-ABC) | 设备: Windows 10/11 · Edge | 位置: 主共享:8443 /照片 | 2.4 MB
```

i.e. "who (IP and reverse-resolved hostname), which device (OS and browser),
where (which share / port / directory), what was done, and the result".

**Level tags are color-coded by behavior** so you can spot things in a wall of text:

| Tag | Color | Meaning |
|------|------|------|
| `[WRITE]` | green/yellow/red | **Write operations**: upload, delete, rename, mkdir (they change the disk — most worth watching) |
| `[READ]` | cyan | Downloads, previews |
| `[BROWSE]` | gray | Directory browsing (high frequency, low value) |
| `[SHARE]` | purple | Share management: create/cancel share, change password, change port |
| `[DENY]` | red | **Access denied**: wrong password, illegal path, insufficient permission, write attempt on a read-only share |
| `[ERROR]` | red | Server exception (usually with a full stack trace) |

`[WRITE]` and `[DENY]` are emphasized; failed lines are colored red in full so
they stand out. Timestamps and levels are bracketed for easy grep/filtering, e.g.
to see only write operations and denials:

```bash
node server.js | grep -E '\[(WRITE|DENY)\]'
```

| Level | What is logged |
|------|----------|
| `quiet` | Only **write operations** (upload / delete / rename / mkdir) and share management |
| `normal` (default) | Write operations + directory browsing, download, preview + **access denied** |
| `verbose` | Additionally logs server exceptions and other diagnostic info |

> The client IP comes from the TCP peer address and cannot be forged via headers
> like `X-Forwarded-For`. The hostname comes from reverse DNS; when it cannot be
> resolved only the IP is shown (a failed lookup never slows the request).

### Terminal colors

- **Colors are disabled automatically when output is redirected to a file or a pipe**,
  so `node server.js > log.txt` produces clean logs without ANSI escape codes —
  easy to read in Notepad or with grep.
- Force on: `FORCE_COLOR=1 node server.js`
- Force off: `NO_COLOR=1 node server.js`
- Windows 10/11 terminals support ANSI colors by default; if a very old conhost
  renders them as garbage, set `NO_COLOR=1`.

---

## 6. Sharing an individual folder

Expose one subfolder on its own port — ideal for "give just this folder to a few people".

- **How to share**: in the main page list, click **"Share"** on the target folder row →
  in the dialog you may enter a port (leave blank to auto-allocate) and optionally set
  an access password → click "Start sharing"; a window then shows the **access URLs**
  (local and all LAN IPs, copyable with one click).
- **Capabilities**: on that port, browse / upload / download / delete / rename /
  preview / live sync are **exactly the same as the main page**, except the root
  becomes that subfolder and it **cannot reach anything outside it**.
- **Who can create**: the **local web UI only**. Whether you access via
  `https://localhost:8443/`, `https://127.0.0.1:8443/`, or the machine's own LAN IP,
  you can create shares; any other device is rejected by the server (403), even on
  the same subnet.
- **No nesting**: a folder that is already shared (and anything inside it) cannot be
  shared again — the server refuses outright, and the "Share" button for such folders
  is greyed out in the main page.
- **Two passwords (read-write / read-only)**: you can set **two separate** passwords
  when creating a share and hand different ones to different people:
  - **Read-write password** — browse, download, upload, delete, rename, mkdir (full access)
  - **Read-only password** — browse, download, preview only; **upload/delete/rename are
    always rejected** (enforced by the server; the UI also hides those buttons and the upload area)
  The two passwords cannot be identical. You may also set just one: with only a
  read-only password the whole share is read-only.
- **Cancel anytime**: the "🔗 Individual shares" panel in the top-right lists all
  shares, copies URLs, **changes the read-write / read-only passwords separately**,
  changes the port, and **cancels a share** (cancelling only closes that port; files
  are not deleted).
- **Log out**: after entering such a port with a password, the same **"🚪 退出登录"**
  button appears in the top-right and clears the password the browser saved.
- **Survives restarts**: share records are stored in `shares.json` next to the
  program (password hashes only, never plaintext) and restored on restart. If a
  directory was deleted or a port is taken, that one entry is skipped with a notice
  in the startup window, without affecting the main service.

---

## 7. Root access password (optional, protects LAN access only)

When you don't want every device on the LAN to read and write the shared folder
directly, put a password in front of the **main share**.

- **How to enable**: open the main page **on the local machine**, click
  **"🔒 访问密码"** in the top-right, type the new password twice and click
  "保存密码" (save). It takes effect **immediately** — no restart needed. Click
  "取消密码保护" to turn it off. (The entry point only exists on the **main share
  page**; share ports neither show it nor can they call the API behind it.)
- **How LAN devices use it**: opening `https://<host-ip>:8443/` makes the browser show
  a username / password dialog (HTTP Basic auth — **the username is ignored, only the
  password matters**). After authenticating, everything works as usual (browse /
  download / upload / delete / rename). A wrong password re-prompts; **6 consecutive
  failures from the same IP are throttled for 60 s** (HTTP 429) so nobody can
  brute-force it with a script.
- **The local machine never needs it**: requests from the machine itself (loopback
  `localhost`, `127.0.0.1`, `::1`, or the machine's own NIC IPs) bypass the prompt —
  decided from the **TCP peer address**, exactly like "share management is local-only",
  and a forged `X-Forwarded-For` header does not help.
- **Main share only**: individual shares keep their own (read-write / read-only)
  passwords and are unaffected by it. Conversely, **a share without a password stays
  reachable without one even when the main share is protected** ("the port is the
  permission") — set a password on that share if you need it.
- **Where it is stored**: as a **salted scrypt hash in `rootauth.json`** next to the
  program, **never plaintext**, and it survives restarts. **Forgot it?** Delete
  `rootauth.json` and restart to disable the protection (or click "取消密码保护" in the
  local UI if you can still get in).
- **Logging**: setting/removing it logs `[SHARE] 修改访问密码`; a wrong password from
  the LAN logs `[DENY] … 根目录访问密码错误或未提供` (denied: root access password
  missing or wrong), and on success the log's "where" field reads
  `主共享:8443(凭访问密码)` so you can tell local access from LAN access with the password.
- **Log out**: once you are in with a password, a **"🚪 退出登录"** button appears in the
  top-right (it is not shown for password-free local access). Clicking it clears the
  credential the browser remembers: the server answers with a 401 challenge, so the
  browser drops the cached password and the next visit asks again. **Note:** click
  "Cancel" in the dialog to actually log out — typing the password again just logs you
  back in. Share ports show the same button when you entered them with a password.

> This is a latch for a **trusted LAN**, **not an account system**: one password for
> the whole site, no users and no per-user permissions, and no "read-only" mode —
> for read-only access use a **read-only password** on an individual share (section 6).

---

## 8. Large uploads & previews

### Chunked upload for large files (resume + auto-retry)

Files over **4MB** automatically use chunked upload, so you never have to redo a
transfer that died halfway:

- **Adaptive chunk size**: starts at 1MB and tunes itself to measured speed
  (targeting ~2 seconds per chunk), ranging from 256KB to 8MB. A fast network grows
  chunks to cut round-trips; a slow network shrinks them to lower the cost of a
  failed chunk.
- **Resume**: each chunk is appended to disk immediately and its progress recorded.
  If the network drops, the browser closes, or even **the server restarts**, the next
  upload of the same file continues from the breakpoint instead of re-sending.
  (State lives in a `<filename>.uploading-chunk` temp file inside the shared folder.)
- **Automatic retry**: a failed chunk is retried automatically with backoff
  0.5s → 1s → 2s → … up to 6 times; if the server's reported progress disagrees with
  the client's (e.g. a lost response), the client realigns to the server's progress.
- **Atomic commit**: once all chunks arrive, the server renames the temp file to the
  target name in one step, so the list never shows a "half file".

### Low-res image preview

With `sharp` installed, uploading an image also generates a low-res preview
(JPEG, 960px on the long edge), so opening a large image:

1. **The low-res image appears instantly** — a notice at the top says "showing
   low-res preview (may be compressed), loading full-res original…"
2. The full-res original keeps downloading in the background and **replaces it
   automatically** when ready; the notice disappears.

So even a multi-megabyte original shows something immediately instead of making you wait.

> The preview is stored as `<original name>.thumb.jpg` next to the image, but it is an
> **internal file**: it never appears in the web list and cannot be downloaded /
> deleted / renamed; deleting or renaming the original updates it in step. If a
> thumbnail is missing (e.g. uploaded without sharp), the first `/thumb` request
> generates it on the fly.

### Video cover preview

With **ffmpeg** installed (optional), videos get a cover image too:

- In the list / icons / tiles / thumbnails views, videos show an **extracted frame**
  (instead of a 🎬 icon)
- ffmpeg extracts the frame at **second 1** (many videos start with black, so second 1
  is more likely to capture real content; if the video is shorter than 1 second it
  falls back to the first frame). It is compressed to a 960px-long-edge JPEG and
  shares the same file as image thumbnails
- Clicking the cover plays the video in the preview layer with a **native player**
  (scrubbing works, thanks to Range support on `/raw`)

> ffmpeg is optional: without it, videos keep the 🎬 icon and nothing else breaks.
> The startup log reports "video cover: enabled / disabled".
> If ffmpeg is not on `PATH`, point `FFMPEG_PATH` at its full path.

### Text preview (txt / logs / configs / code)

Read a file's content without downloading it first:

- Text files have a **"预览"** (preview) button on the right of the row; in the icon /
  tile / thumbnail views you can also click the 📄 icon.
- Supported: `txt` `log` `md` `json` `csv` `xml` `yml` `ini` `conf` `sql` `js` `css`
  `html` `bat` `ps1` `sh` `py` `java` `c` `cpp` `go` `rs` and friends, plus
  extension-less files such as `README` / `LICENSE` / `Dockerfile` / `.gitignore`.
- The preview is a **read-only** monospace view (long lines wrap, the box scrolls);
  ← / → move through images, videos and text files in the same directory, Esc or a
  click on the background closes it.
- **Only the first 1 MB is read**, so huge logs cannot freeze the browser; beyond that
  a notice says "only the first 1 MB is shown, download for the full file".
- **Encoding is detected**: UTF-8 first, falling back to GB18030 — text files saved by
  Notepad on a Chinese Windows are usually GBK, which would look garbled as UTF-8.
- Content is rendered with `textContent` (never `innerHTML`), so HTML/JS files show up as
  **source text** and are never executed (no XSS).

### Preview caching (ETag / 304)

Both preview originals and thumbnails carry `ETag` and `Last-Modified`:

- **Reopening the same image does not re-download it** — the browser uses its local
  cache; even when the cache expires it receives a zero-byte `304` response instead
  of the whole original
- If the file is **overwritten in place**, the `ETag` changes and the browser
  automatically fetches the new image, so **you never see a stale one**
- There is also a **front-end in-memory cache** (the last 12 originals per page
  session), so repeated previews make zero network requests

> This layer matters especially over tunnels (NAT traversal), whose bandwidth is
> usually far below the LAN's; avoiding repeated original transfers noticeably
> improves the preview experience.

---

### Batch download (ZIP packaging)

When you want to take away several files or a whole folder at once:

1. **Tick** the items you need in any view — every row has a checkbox at its start and
   every tile has one at its top-left; "Select all" picks the whole current directory.
2. Click **"⬇ Download selected"** in the toolbar:
   - **exactly one file ticked** → the original file downloads **directly, without packaging**
     (no waiting for packaging, no temporary disk usage);
   - **several items, or a folder** → the server packages a ZIP first (a folder has to be
     packaged to be taken away in one go).

Details:

- **Folders are packaged recursively**, including every nested level; empty folders
  are preserved.
- **The archive keeps the directory structure**: ticking `docs/a.txt` and `photos` in
  the root yields `docs/a.txt`, `photos/p1.txt`, `photos/sub/deep.txt` after
  extraction — the hierarchy matches the original and does not spill into a flat pile.
- **No extra nesting**: packaging `photos` extracts to `photos/...`, not `photos/photos/...`.
- The package **excludes** internal files such as auto-generated thumbnails.
- If any selected item has been deleted or is inaccessible, it is **skipped and the
  rest still packages** — the whole download does not fail.
- At most 500 items at a time.
- Package name: the item's name for a single selection; otherwise
  `current_dir_name_item_count.zip`.
- **Packaging is fast**: over a LAN there is no point burning CPU to save a few bytes —
  formats that are already compressed (jpg / png / mp4 / mp3 / zip / pdf / docx / apk …)
  are **stored** without a second compression pass, everything else uses the **fastest**
  deflate level. Measured: 220 files / 160 MB went from 7.2 s to 0.7 s (≈220 MB/s, i.e.
  disk speed), while text still compresses to about 1% of its original size.
- **The progress follows the real transfer**: during packaging the page shows
  "processed N of M items"; once the download starts it shows
  **"downloading… 12.3 MB / 160.1 MB (8%)"**, and "download complete" appears only when
  the transfer has actually finished. An interruption immediately shows "download
  interrupted…" and clicking again resumes.
- **Supports resume**: the download is an ordinary file URL (with `Accept-Ranges`), so an
  **interrupted, paused, or closed-and-reopened** download continues instead of
  restarting; multi-threaded download tools work too.
- **Two-phase flow**: the server first packages the ZIP, then the download starts — the
  trade-off for resumable downloads.
- **Packages are reused**: clicking "Download selected" again with the same selection
  within 6 hours reuses the existing package instead of repacking.

> Why not "compress while streaming": a ZIP's central directory is written at the end
> of the file and a streaming response cannot seek, so an interruption would force a
> full restart. For tens of GB that is unacceptable in practice, hence writing to disk
> first. Temporary packages live in the **system temp directory**
> (`%TEMP%\lan-file-share-zips`, outside the shared folder) and are kept for 6 hours
> before automatic cleanup.

> Requires the `archiver` dependency. Without it, "Download selected" reports that it
> is unavailable, but **single-file downloads are completely unaffected**.

---

## 9. Manual CLI (optional)

```bash
node gen-cert.js            # run once, only when there is no certificate (needs openssl)
node server.js              # start

# or with npm, if you prefer
npm run cert                # generate the certificate
npm start                   # start
```

---

## 10. Advanced / operations notes

- **Windows firewall**: if other devices cannot connect on first run, make sure the
  TCP port in use is allowed through the system firewall; the browser must visit the
  target computer's **LAN IP**, not `localhost`.
- **IPv6**: the server listens on **both** address families by default, so the same port
  works over IPv4 and IPv6.
  - The Windows firewall treats IPv4 and IPv6 **separately**: if only IPv6 fails, allow
    the port for IPv6 as well (Advanced Windows Defender Firewall → Inbound Rules, TCP,
    local port = your port).
  - **Link-local addresses** (`fe80::/10`) require a NIC zone ID, e.g.
    `https://[fe80::1a2b:3c4d:5e6f:7a8b%12]:8443/` (browsers also accept `%25`), which is
    why startup only reports how many exist instead of listing URLs.
  - The certificate SAN now covers **both IPv4 and IPv6 addresses**, so browsing over
    IPv6 no longer triggers a "certificate name mismatch"; **temporary IPv6 addresses
    (privacy extensions) change over time**, though — re-run `node gen-cert.js` when
    that happens, or simply use the IPv4 address.
  - On a system with IPv6 disabled the startup line ("监听方式") says IPv4-only and
    everything keeps working.
- **Changing the port**: edit `port` in `config.json` and restart — no need to
  regenerate the certificate (it contains IPs, not the port).
- **Changing subnet / IP**: regenerate the certificate (if the SAN only lists the old
  IP, devices will fail validation).
- **Public exposure risk**: the program has **no account system** and is meant for a
  trusted LAN only. Do **not** map the port to the internet. A root access password
  (section 7) or per-share passwords can keep casual LAN visitors out, but they are a
  latch inside a trusted network, not a security measure for the public internet.
  If you need concurrent users, rate limiting, or WebSocket-resumable uploads, that can
  be added later.
- **Live sync**: the service runs a recursive `fs.watch` on the shared folder and also
  broadcasts after every write endpoint; browsers receive it over SSE
  (`/api/events`). If a filesystem does not support recursive watching, a notice is
  printed at startup and only "writes made by this service itself" sync live. Each
  port receives only changes **within its own scope**: a shared port never sees
  activity in other directories.
- **Ports for individual shares**: each share listens on an extra HTTPS port; remember
  to allow those ports through the system firewall too.
- **Logs record IPs**: the action log contains visitor IPs and reverse-resolved
  hostnames; if you don't want that, `logLevel: quiet` still logs write operations —
  or use stricter network isolation.
- **Large uploads / slow links**: uploads stream to disk without large memory use;
  downloads stream with resume support.

---

## 11. Directory-structure security

- Every request path goes through `realpath` + bounds checking, so `../`,
  symbolic links, or directory junctions cannot reach files outside the shared folder.
- Uploads reject names containing `/`, `\`, NUL, `.` or `..`; on Windows they also
  reject `: * ? " < > |`, trailing dots/spaces, and the reserved names
  `CON/PRN/AUX/NUL/COM1..9/LPT1..9` (preventing writes to NTFS alternate data streams
  or leftover zero-byte same-named files).
- Uploads write to a temp file first and rename atomically, so an interrupted client
  never leaves a truncated, falsely-successful file.
- Deletion is limited to paths inside the shared folder, and deleting the share root
  itself is forbidden; delete/rename only act on resolved real paths within the share.
  Deletion is **permanent and recursive** (the whole folder) and cannot be undone.
- **Executable content** such as HTML / SVG / JS is always served as an attachment;
  `/raw` previews additionally carry `CSP sandbox` and
  `X-Content-Type-Options: nosniff`, eliminating stored XSS from files in the shared
  folder at the root.
- Directory creation and uploads are equally confined to the share root; `../` or empty
  segments cannot escape it.
- **Each share port has its own root**: every path on that port is confined to the
  shared subfolder, and `../`, sibling directories, or anything outside the share root
  returns 403. The capabilities match the main page, but the view is smaller.
- **Share management is local-only**: creating/cancelling shares, changing passwords,
  and viewing logs all verify that the TCP peer address belongs to this machine
  (loopback or one of its own NIC IPs); other devices get 403, and forging
  `X-Forwarded-For` has no effect.
- **Cross-site request protection (CSRF)**: every non-`GET/HEAD` request is checked
  against `Origin` and `Sec-Fetch-Site`; anything coming from **another site** (including
  `Origin: null`) is rejected with 403, and JSON endpoints additionally **only accept
  `Content-Type: application/json`** — the `text/plain` / `x-www-form-urlencoded` bodies a
  form can produce are never parsed. This closes the chain "admin opens a malicious page
  in the local browser → it submits an `enctype=text/plain` form to /api/share/create →
  an external share of an arbitrary directory is created without a password": the
  peer address of such a request *is* local, so "local only" alone cannot stop it.
- **Packaged results are scoped**: `/api/download-zip/status` and `/get` verify which
  scope owns the task, so another share port (or the main port) gets a 404 even with a
  valid zipId — no cross-scope downloads.
- **Root access password (optional, see section 7)**: once set, **every request from a
  non-local source** on the main port is challenged with HTTP Basic first. The password
  is stored as a **salted scrypt hash** (never plaintext) and compared in **constant
  time**; **6 consecutive failures from one IP trigger a 60 s throttle** (HTTP 429) so
  it cannot be brute-forced from a script, and concurrent verifications are capped so a
  flood of attempts cannot stall the service. Local sources (loopback and the machine's
  own NIC IPs, decided from the TCP peer address) never need the password — the same
  check used for "share management is local-only" — and the set/remove API is local-only
  as well.
- **No nested shares**: an already-shared folder and anything inside it cannot be
  shared again, and this is enforced server-side.
- **Thumbnails / video covers are internal files**: `<name>.thumb.jpg` never appears
  in the list and cannot be accessed or modified via `/download`, `/raw`,
  `/api/delete`, or `/api/rename`; it is only obtainable through
  `/thumb?path=<original path>`, which is itself protected by bounds checking and
  carries `CSP: sandbox` and `nosniff`.
- **Chunked uploads are equally restricted**: `/api/upload/chunk`,
  `/api/upload/finish`, and `/api/upload/status` apply the same target-directory
  validation as normal uploads, so the chunk API cannot write outside the share root.
- **Batch packaging is equally restricted**: every item in `/api/download-zip` is
  bounds-checked independently (traversal is rejected/skipped), and archive entry
  names use only paths relative to the share root — **no drive letters or `..`** — so
  extraction cannot write outside the target directory (Zip Slip protection).
  Recursive packaging **skips symbolic links**, so it cannot pull content from outside
  the share root through a link.

### Known boundaries (this is a "trusted-LAN tool", not a public service)

- **The main share has no authentication by default**: unless a root access password is
  set, any device on the LAN can browse, upload, rename, and permanently delete its
  content; and with a password it only **blocks LAN sources** (the local machine stays
  exempt), with a single password for the whole site and no user/permission tiers.
  (Individual shares have an **optional** password — read-write or read-only — but that
  is an isolation measure for "sharing with a few people", not a full account system.)
- The service reads/writes files as the user who started it and **does not isolate
  permissions**; share only a dedicated directory, never a system-drive root or your
  user directory.
- Uploaded content is not validated and not virus-scanned; anything uploaded can be
  downloaded by anyone.
- Individual shares are "the port is the permission": with no password, any device
  that can reach the port can use it — set a password as needed.

---

### What I have built and verified

- ✅ Directory browsing (Chinese-aware sorting, folders first, breadcrumbs, entering subfolders)
- ✅ View switching (list / icons / tiles / thumbnails + size slider, choice remembered)
- ✅ File download (as attachment) + Range resume + HEAD
- ✅ Image preview: instant low-res + automatic full-res replacement + compression notice; click blank to go back, arrow keys to navigate
- ✅ Video cover (ffmpeg frame extraction) + inline playback (native player / Range scrubbing)
- ✅ Preview caching: ETag + 304 negotiation + front-end memory cache, so repeated previews never re-transfer originals
- ✅ File/folder upload (streaming, recursive over spaced directories, overwritable, configurable size cap)
- ✅ Large-file chunked upload (adaptive chunking + resume + auto-retry, resumable even after a restart)
- ✅ Batch download (tick/select-all → ZIP packaging, recursive folders, structure preserved, **resumable Range download after packaging**)
- ✅ Low-res image thumbnails (sharp, async generation / on-demand rebuild / internal-file isolation / rename-and-delete in step)
- ✅ Rename (files and folders), delete (files and folders, recursive, confirmed, root protected)
- ✅ Path traversal / out-of-bounds protection, symlink and directory-junction protection (tested with real junctions)
- ✅ Stored-XSS protection (executable content forced to attachment + CSP sandbox + nosniff)
- ✅ Live silent sync (SSE + fs.watch, verified on both ends: change on one side, the other page updates without reloading)
- ✅ Individual folder sharing (dedicated port + dedicated scope + optional password + no nesting + restart recovery)
- ✅ Read-write / read-only dual passwords (the server enforces no-write for read-only; the UI hides write entry points)
- ✅ Action log (who / device / where / what / result, three verbosity levels)
- ✅ Colored terminal logs (color by behavior + level tags, auto-degrades to no color when redirected)
- ✅ Share management available only locally (loopback and local NIC IPs work; other devices get 403)
- ✅ IPv4 + IPv6 dual-stack listening (share ports and WebDAV too; falls back to IPv4 when the
  system has no IPv6, and startup lists both address families — link-local only as a count)
- ✅ Root access password (set from the local web UI, effective immediately, scrypt hash only in
  `rootauth.json`, LAN 401 challenge / local machine exempt / per-IP failure throttle 429 /
  live-sync connections dropped the moment it changes)
- ✅ Log out (shown only when you got in with a password; `/logout` answers 401 so the browser
  drops the cached credential, repeated hits from one IP are challenged only once every 20 s to
  avoid a dialog loop, and read-only passwords can log out too)
- ✅ Text preview (txt / logs / configs / code, read-only, first 1 MB only, UTF-8 → GB18030
  fallback, rendered via `textContent` so nothing executes, images/videos/text pageable together)
- ✅ Single-file direct download (a one-file selection is no longer packaged, saving both the wait
  and the temporary disk usage)
- ✅ CSRF protection (non-GET/HEAD requests are checked against Origin / Sec-Fetch-Site and
  cross-site ones get 403; JSON endpoints only accept `application/json`; reproduced with an
  external-Origin `text/plain` form PoC and verified closed)
- ✅ Packaged results scoped to their owner (another port gets 404 for both status and download,
  same-scope keeps working)
- ✅ Faster packaging (already-compressed formats stored as-is + fastest deflate for the rest:
  measured 160 MB / 220 files from 7.2 s to 0.7 s)
- ✅ Real download progress (byte-accurate server counters polled by the page: packaging →
  downloading x% → complete / interrupted)
- ✅ Automatic self-signed HTTPS certificate generation (SANs for every LAN IPv4 / IPv6 address)
