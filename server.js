'use strict';

/**
 * lan-file-share —— 零依赖 Node.js 局域网 HTTPS 文件共享服务器
 *
 * 功能:
 *   1. 网页目录浏览(面包屑导航、目录/文件列表、大小与修改时间)
 *   2. 文件下载(支持 Range 断点续传)与内联预览(图片/文本/PDF 等)
 *   3. 拖拽 / 选择文件上传到当前目录(流式写盘,不占内存)
 *   4. 全程 HTTPS,配置文件为同目录 config.json;默认 IPv4 + IPv6 双栈监听,
 *      启动时把本机各局域网地址(含 IPv6)都列出来
 *   5. 实时静默同步:任一设备改动,其它正在浏览的页面自动更新
 *   6. 单独分享文件夹:把共享根内某个子文件夹单独开一个端口对外(可选口令),
 *      仅本机网页端可创建/取消,且不支持在已分享的文件夹里再分享一层
 *   7. 根目录访问密码(可选):在本机网页端设置后,局域网设备访问主共享要先输入密码,
 *      本机(回环与本机网卡 IP)按设计免输;密码以 scrypt 哈希存于同目录 rootauth.json
 *   8. 操作日志:谁(IP/主机名)从哪里、用什么设备、对什么做了什么
 *
 * 使用:
 *   node gen-cert.js   # 首次使用:生成自签名证书(需 openssl)
 *   node server.js     # 启动服务
 *
 * 安全边界:
 *   - 所有相对路径经 realpath 校验必须落在该监听器的根目录之内,防 ../ 与符号链接逃逸
 *   - 上传文件名不允许包含路径分隔符
 *   - 单独分享可设读写/只读口令;主共享可选「根目录访问密码」(只拦局域网来源,
 *     本机访问免输);除此之外没有账号体系,仅适用于可信局域网,请勿暴露到公网
 */

const https = require('node:https');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { pipeline } = require('node:stream/promises');

const ROOT_DIR = __dirname;
const CONFIG_PATH = path.join(ROOT_DIR, 'config.json');
const STATE_PATH = path.join(ROOT_DIR, 'shares.json'); // 单独分享的持久化记录
const ROOT_AUTH_PATH = path.join(ROOT_DIR, 'rootauth.json'); // 主共享「根目录访问密码」的持久化记录(只存哈希)

let CONFIG;
try {
  CONFIG = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
} catch (e) {
  errorLine(`无法读取配置文件 ${CONFIG_PATH}: ${e.message}`);
  process.exit(1);
}

const SHARE_ROOT = path.resolve(ROOT_DIR, CONFIG.shareRoot || 'share');
const CERT_FILE = path.resolve(ROOT_DIR, CONFIG.certFile || 'certs/server.crt');
const KEY_FILE = path.resolve(ROOT_DIR, CONFIG.keyFile || 'certs/server.key');
const PORT = Number(CONFIG.port) || 8443;
const MAX_UPLOAD_BYTES = (Number(CONFIG.maxUploadMB) > 0 ? Number(CONFIG.maxUploadMB) * 1024 * 1024 : 0);
const ALLOW_OVERWRITE = CONFIG.allowOverwrite !== false;
const PAGE_TITLE = CONFIG.title || '局域网文件共享';
// 单独分享的端口从该值起自动寻找空闲端口(也允许在创建时手动指定)
const SHARE_PORT_BASE = Number(CONFIG.sharePortBase) > 0 ? Number(CONFIG.sharePortBase) : 9000;
// 操作日志详细程度: quiet(仅写操作) | normal(默认,含访问与写操作) | verbose(含每个请求)
const LOG_LEVEL = ['quiet', 'normal', 'verbose'].includes(CONFIG.logLevel) ? CONFIG.logLevel : 'normal';

const collator = new Intl.Collator(['zh', 'en'], { numeric: true, sensitivity: 'base' });

/* ---------------- 路径安全 ---------------- */

// 越界判定的基准用根的“真实路径”:若根目录本身是符号链接/目录联接,
// 直接用配置字符串做前缀比较会把所有合法访问都误判成越界。启动时校正为 realpath。
let SHARE_ROOT_REAL = SHARE_ROOT;

const IS_WIN = process.platform === 'win32';
// Windows 文件名禁用字符。路径段或文件名中出现一律拒绝:否则 NTFS 备用数据流(如
// "a.txt:evil")会把内容写到预期之外的数据流里,且失败后会残留一个 0 字节同名文件。
const INVALID_SEGMENT_CHARS = IS_WIN ? /[:*?"<>|\x00-\x1f]/ : /\x00/;
const WIN_RESERVED_NAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function isInside(root, abs) {
  const rel = path.relative(root, abs);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// 低清预览图以 "<原文件名>.thumb.jpg" 与图片同目录存放。它是本服务的内部文件:
// 不出现在目录列表,也不能通过 /download、/raw、/api/delete、/api/rename 等接口直接操作。
const THUMB_SUFFIX = '.thumb.jpg';
function isThumbName(name) {
  return String(name).toLowerCase().endsWith(THUMB_SUFFIX);
}

/**
 * 每个监听端口对应一个“共享作用域”。主端口与各单独分享端口共用同一套路由与安全校验,
 * 差别只在 root / rootReal / 是否允许再嵌套分享 / 口令。
 * ctx = { kind:'main'|'share', root, rootReal, title, allowNestedShare, needPwd, token, port, view }
 */
function makeCtxMain() {
  return {
    kind: 'main',
    root: SHARE_ROOT,
    rootReal: SHARE_ROOT_REAL,
    title: PAGE_TITLE,
    allowNestedShare: true,   // 只有主端口能创建/取消单独分享
    needPwd: false,
    token: '',
    port: PORT,
    view: 'main',
  };
}

/** 把某个作用域内的相对路径换算成「主共享根内的相对路径」(广播统一用主共享视角)。 */
function mainRelOf(ctx, rel) {
  const r = String(rel || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!ctx || ctx.kind === 'main') return r;
  const sh = shares.get(ctx.shareId);
  if (!sh) return r;
  return r ? `${sh.rel}/${r}` : sh.rel;
}

/** 把主端口的 ctx 换成某个单独分享端口的作用域。 */
function makeCtxShare(sh) {
  return {
    kind: 'share',
    // root 一律用记录里的绝对路径 sh.absRoot:
    //   - 共享根内的分享:absRoot = 共享根 + 该相对路径
    //   - 外部文件夹分享(管理员指定):absRoot 就是那个绝对路径
    // 这样这里不必再做拼接,避免外部路径被错误地拼到共享根之下。
    root: sh.absRoot || path.resolve(SHARE_ROOT, sh.rel),
    rootReal: sh.real,
    title: `${sh.name} · 单独分享`,
    allowNestedShare: false,  // 已分享的文件夹内不能再分享
    needPwd: !!sh.pwdHash || !!sh.roHash,
    token: sh.token,
    port: sh.port,
    view: 'share',
    shareId: sh.id,
    external: !!sh.external,  // 是否来自共享根之外(日志与界面用于区分)
    // 每个请求会按携带的口令把 role 覆盖成 'rw' / 'ro';'ro' 时禁止一切写操作
    role: 'rw',
  };
}

/**
 * 校验用户提交的单级名称(文件名 / 重命名新名)。合法则返回原名称,否则抛 HttpError。
 * 名称只能是单级:不含 / \ 与空字节,也不是 . / .. ;
 * Windows 上再拒绝禁用字符、结尾的点/空格以及保留设备名(CON/PRN/NUL/COM1 等)。
 */
function assertEntryName(rawName) {
  if (typeof rawName !== 'string' || rawName === '' || rawName === '.' || rawName === '..'
      || rawName.includes('\0') || rawName.includes('/') || rawName.includes('\\')) {
    throw new HttpError(400, '缺少或非法的名称');
  }
  if (IS_WIN) {
    if (INVALID_SEGMENT_CHARS.test(rawName)) throw new HttpError(400, '名称包含系统不支持的字符');
    if (/[. ]$/.test(rawName)) throw new HttpError(400, '名称不能以点或空格结尾');
    if (WIN_RESERVED_NAME.test(rawName)) throw new HttpError(400, '该名称是系统保留名,不能使用');
  }
  return rawName;
}

/**
 * 校验“共享根内相对路径”里的一层目录名。复用 assertEntryName 的 Windows 规则,
 * 避免出现「文件名不允许、但作为路径段却允许」的不一致(如 CON、结尾的点/空格)。
 */
function assertRelSegment(seg) {
  if (seg === '' || seg === '.' || seg === '..' || INVALID_SEGMENT_CHARS.test(seg)) {
    throw new HttpError(400, '非法路径参数');
  }
  if (IS_WIN) {
    if (/[. ]$/.test(seg)) throw new HttpError(400, '路径中的名称不能以点或空格结尾');
    if (WIN_RESERVED_NAME.test(seg)) throw new HttpError(400, '路径中含系统保留名,不能使用');
  }
}

/**
 * 把客户端传来的“共享目录内相对路径”(使用 / 分隔)解析为位于该根目录之内的
 * 绝对路径(target 必须真实存在)。调 realpath 校验,防 ../ 与符号链接逃逸;
 * 返回 { abs } 为归一化后的真实绝对路径。文件与目录均可,由调用方判定类型。
 * throws: 附带用户可读信息的 HttpError
 */
async function resolveExisting(ctx, relStr) {
  if (typeof relStr !== 'string' || relStr.includes('\0')) {
    throw new HttpError(400, '非法路径参数');
  }
  let rel = relStr.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (rel === '') {
    const real = await fsp.realpath(ctx.root);
    if (!isInside(ctx.rootReal, real)) throw new HttpError(403, '拒绝访问共享目录之外的位置');
    return { abs: real };
  }
  const parts = rel.split('/');
  for (const p of parts) assertRelSegment(p);
  // 低清预览图是本服务的内部文件:不允许通过 /download、/raw、/api/delete、/api/rename
  // 等任何接口直接操作(列表里也已隐藏)。缩略图只能由 /thumb 按原图路径访问。
  if (isThumbName(parts[parts.length - 1])) {
    throw new HttpError(404, '文件或目录不存在');
  }
  const abs = path.resolve(ctx.root, ...parts);

  const real = await fsp.realpath(abs);
  if (!isInside(ctx.rootReal, real)) throw new HttpError(403, '拒绝访问共享目录之外的位置');
  return { abs: real };
}

/* ---------------- HTTP 辅助 ---------------- */

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

/* ---------------- MIME ---------------- */

const MIME = {
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.xml': 'application/xml; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.bmp': 'image/bmp',
  '.pdf': 'application/pdf', '.zip': 'application/zip', '.gz': 'application/gzip',
  '.7z': 'application/x-7z-compressed', '.rar': 'application/vnd.rar',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
  '.m4v': 'video/x-m4v', '.mkv': 'video/x-matroska', '.avi': 'video/x-msvideo',
  '.wmv': 'video/x-ms-wmv', '.flv': 'video/x-flv', '.ts': 'video/mp2t',
  '.mpg': 'video/mpeg', '.mpeg': 'video/mpeg', '.3gp': 'video/3gpp',
  '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
  '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.exe': 'application/octet-stream', '.msi': 'application/octet-stream', '.apk': 'application/vnd.android.package-archive',
};
function mimeOf(name) {
  return MIME[path.extname(name).toLowerCase()] || 'application/octet-stream';
}
// 浏览器能否内联预览(图片/文本/PDF/音视频)
function isInlineable(name) {
  const m = mimeOf(name).split(';')[0];
  return m.startsWith('image/') || m.startsWith('text/') || m === 'application/pdf'
    || m.startsWith('video/') || m.startsWith('audio/') || m === 'application/json'
    || m === 'application/xml' || m === 'image/svg+xml';
}

function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

/* ---------------- 目录列表 API ---------------- */

async function listDir(ctx, relStr) {
  const { abs } = await resolveExisting(ctx, relStr);
  const st = await fsp.stat(abs);
  if (!st.isDirectory()) throw new HttpError(400, '该路径不是目录');

  const names = await fsp.readdir(abs);
  const entries = [];
  for (const name of names) {
    if (name === '.' || name === '..') continue;
    // 本服务生成的低清预览图是内部文件,不展示给用户(避免看起来像"多出来的怪文件")
    if (isThumbName(name)) continue;
    let stt;
    try { stt = await fsp.stat(path.join(abs, name)); } catch { continue; } // 损坏的符号链接等
    entries.push({
      name,
      isDir: stt.isDirectory(),
      size: stt.isDirectory() ? null : stt.size,
      mtime: stt.mtimeMs,
    });
  }
  entries.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return collator.compare(a.name, b.name);
  });

  const parts = (relStr || '').replace(/\\/g, '/').split('/').filter(Boolean);
  let acc = '';
  const crumbs = parts.map((p) => { acc += (acc ? '/' : '') + p; return { name: p, path: acc }; });
  // publish 为该目录在共享根内的规范化相对路径,前端直接用它做变更匹配与静默刷新
  const publish = parts.join('/');
  return { dir: publish, crumbs, entries, publish };
}

/* ---------------- 文件传输 ---------------- */

function contentDisposition(name, inline) {
  if (inline) return 'inline';
  const ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii || 'download'}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/**
 * 加载打包器。archiver 8.x 改成了导出类的形式(不再导出一个可直接调用的函数):
 *   - 8.x:用 `ZipArchive`(它内部才真正挂上 zip 模块;直接用 Archiver 会运行时报错)
 *   - 7.x 及更早:导出的是可调用函数 `archiver('zip', opts)`
 * 这里两种都兼容,避免以后升级/降级依赖时又要改代码。
 */
let archiverLib = null;
let archiverLoadTried = false;
function loadArchiver() {
  if (archiverLoadTried) return archiverLib;
  archiverLoadTried = true;
  try {
    const mod = require('archiver');
    if (typeof mod === 'function') archiverLib = { create: (opts) => mod('zip', opts) };
    else if (typeof mod.ZipArchive === 'function') archiverLib = { create: (opts) => new mod.ZipArchive(opts) };
    else archiverLib = null;
  } catch { archiverLib = null; }
  return archiverLib;
}

/**
 * 批量下载:把选中的多个文件/文件夹打包成一个 ZIP 流式返回。
 *
 * 安全要点:
 *   - 每一项都走 resolveExisting 校验(必须真实存在于该共享根内),防 ../ 与符号链接逃逸;
 *   - 压缩包内的路径只取“根到该项的相对路径”,绝不含盘符或 .. ,避免解开时写到目录外(Zip Slip);
 *   - 递归打包时跳过符号链接,避免顺着链接把共享根外的内容打进包里;
 *   - 单项失败(被删/无权限)只跳过该项并记录,不让整个下载失败。
 */
/* ---------------- 批量打包下载(ZIP) ---------------- */

/**
 * 批量下载采用「先打包落盘、再按 Range 下发」的两段式,解决大包传一半断了要重来的问题:
 *
 *   1. POST /api/download-zip/prepare  → 服务端在系统临时目录生成 ZIP,返回一个 zipId
 *      (打包过程可查询进度;同一个选择重复请求会复用已完成的包)
 *   2. GET  /api/download-zip/get?id=… → 按普通文件那样支持 Range 断点续传、多线程下载
 *
 * 为什么不在线边压边传:ZIP 的中央目录写在文件末尾,流式响应没法随机定位,
 * 一旦中断整个包就得从头再来。对动辄几十 GB 的共享目录,这在实际使用中不可接受。
 */

const ZIP_TMP_DIR = path.join(os.tmpdir(), 'lan-file-share-zips');
const ZIP_TTL_MS = 6 * 60 * 60 * 1000;      // 打包结果保留 6 小时,之后自动清理
const zips = new Map();                      // id -> { file, size, name, ready, total, added, error, at, key, req }

/** 确保临时目录存在。 */
function ensureZipDir() {
  try { fs.mkdirSync(ZIP_TMP_DIR, { recursive: true }); } catch { /* 已存在或无权限,后续写入会报错 */ }
}

/** 清理过期的打包结果(定时 + 每次新建时顺手做一次)。 */
function cleanupZips() {
  const now = Date.now();
  for (const [id, z] of zips) {
    if (now - z.at < ZIP_TTL_MS) continue;
    if (!z.ready && !z.error) continue;       // 还在打包中,不动
    try { fs.rmSync(z.file, { force: true }); } catch {}
    zips.delete(id);
  }
}
setInterval(cleanupZips, 30 * 60 * 1000).unref?.();

/** 把选择项解析为真实路径(逐项校验越界),并算出包内名字。 */
async function resolveZipItems(ctx, req, url) {
  const raw = url.searchParams.get('paths') || '';
  const picked = raw.split('\n').map((s) => s.trim()).filter(Boolean);
  if (!picked.length) throw new HttpError(400, '没有选择要下载的内容');
  if (picked.length > 500) throw new HttpError(400, '一次最多打包 500 项,请分批下载');

  // 前端传的 paths 已经是「相对共享根」的完整路径(例如 照片/2026_09_30/a.jpg),
  // 所以这里不再拼 dir —— dir 只用来把包内路径还原成「相对当前目录」。
  // (之前这里拼过一次 dir,导致子目录下变成 子目录/子目录/文件,必然 404。)
  const curDir = (url.searchParams.get('dir') || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const items = [];
  for (const name of picked) {
    const rel = name.replace(/\\/g, '/').replace(/^\/+/, '');
    try {
      const { abs } = await resolveExisting(ctx, rel);
      const st = await fsp.stat(abs);
      // 每个条目都重新做一次真实路径校验,并确认它仍在共享根内(防检查后替换的竞态)
      const real = await fsp.realpath(abs);
      if (!isInside(ctx.rootReal, real)) throw new HttpError(403, '拒绝访问共享目录之外的位置');
      // 包内名字:去掉「当前目录」前缀,这样在 照片/2026_09_30 里勾选 a.jpg,解压出来就是 a.jpg
      let inner = rel;
      if (curDir && (rel === curDir || rel.startsWith(curDir + '/'))) inner = rel.slice(curDir.length).replace(/^\/+/, '');
      items.push({ rel, name: inner || rel.split('/').pop(), abs: real, isDir: st.isDirectory() });
    } catch (e) {
      // 单个条目失效不影响其余(例如已在别处被删除)
      logAction({ action: 'deny', ctx, req, path: rel, ok: false,
                  status: (e && e.status) || 404, detail: '批量下载时该项不可用,已跳过' });
    }
  }
  if (!items.length) throw new HttpError(404, '所选内容都不可用(可能已被删除或移动)');

  // 顶层重名时自动去重。条目名保留「相对当前目录」的结构
  // (例如在 照片/ 下选 子目录/deep.txt → 包内为 子目录/deep.txt),避免解压后层级丢失。
  const used = new Set();
  for (const it of items) {
    let name = it.name.replace(/^\/+/, '');
    if (used.has(name)) {
      const base = name;
      let n = 2;
      while (used.has(name)) name = `${base} (${n++})`;
    }
    used.add(name);
    it.zipRoot = name;
  }
  return items;
}

/** 算出压缩包文件名。 */
function zipNameFor(items, url) {
  const dirName = (url.searchParams.get('dir') || '').split('/').filter(Boolean).pop() || '共享文件';
  return items.length === 1 ? `${items[0].zipRoot}.zip` : `${dirName}_${items.length}项.zip`;
}

/** 用一个稳定 key 表示"这次选择",便于重复请求复用同一个包。 */
function zipKeyOf(ctx, url, items) {
  const scope = ctx.kind === 'main' ? 'main' : (ctx.shareId || 'share');
  const dir = (url.searchParams.get('dir') || '').replace(/\\/g, '/');
  return `${scope}|${dir}|${items.map((x) => x.rel + (x.isDir ? '/' : '')).join('\n')}`;
}

/**
 * 第一步:准备压缩包(落盘到系统临时目录)。
 * 立即返回 zipId;真正的打包在后台进行,前端可轮询进度。
 */
async function handleZipPrepare(ctx, req, res, url) {
  const lib = loadArchiver();
  if (!lib) throw new HttpError(503, '服务端未安装 archiver,请运行 npm install archiver');

  const items = await resolveZipItems(ctx, req, url);
  const zipName = zipNameFor(items, url);
  const key = zipKeyOf(ctx, url, items);

  // 同一个选择且包已就绪 → 直接复用(用户重试/刷新页面时不必重新打包)
  for (const [id, z] of zips) {
    if (z.key === key && z.ready && !z.error) {
      z.at = Date.now();
      return sendJson(res, 200, { ok: true, id, name: z.name, size: z.size, reused: true });
    }
    if (z.key === key && !z.ready && !z.error) {
      return sendJson(res, 200, { ok: true, id, name: z.name, pending: true });
    }
  }

  cleanupZips();
  ensureZipDir();
  const id = 'z' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const file = path.join(ZIP_TMP_DIR, `${id}.zip`);

  const entry = { id, file, name: zipName, size: 0, ready: false, error: '', at: Date.now(),
                  key, total: 0, added: 0, items: items.length };
  zips.set(id, entry);

  // 后台打包:先写临时文件,写完再原子改名,避免半成品被下载
  const part = file + '.part';
  const out = fs.createWriteStream(part);
  const archive = lib.create({ zlib: { level: 6 } });
  archive.on('error', (e) => { entry.error = e.message; try { out.destroy(); } catch {} });
  out.on('error', (e) => { entry.error = e.message; });
  out.on('close', () => {
    if (entry.error) { try { fs.rmSync(part, { force: true }); } catch {} return; }
    try {
      const st = fs.statSync(part);
      fs.renameSync(part, file);
      entry.size = st.size;
      entry.ready = true;
      entry.at = Date.now();
      logAction({
        action: 'download', ctx, req: entry.req || req,
        path: items.map((x) => x.rel).join(', ').slice(0, 200), ok: true,
        detail: `打包 ${entry.added} 个文件为 ${zipName}(${fmtSize(st.size)})`,
      });
    } catch (e) { entry.error = e.message; }
  });
  archive.pipe(out);
  entry.req = req;

  (async () => {
    for (const it of items) {
      if (entry.error) break;
      try {
        if (it.isDir) entry.added += await addDirToArchive(archive, it.abs, it.zipRoot, entry);
        else { archive.file(it.abs, { name: it.zipRoot }); entry.added++; entry.total++; }
      } catch (e) {
        errorLine(`打包「${it.rel}」失败: ${e.message}`);
      }
    }
    if (!entry.added) {
      entry.error = '所选内容都不含可打包的文件';
      try { archive.abort(); out.destroy(); } catch {}
      return;
    }
    try { await archive.finalize(); } catch (e) { entry.error = e.message; }
  })();

  return sendJson(res, 200, { ok: true, id, name: zipName, pending: true });
}

/** 查询打包进度。 */
function handleZipStatus(ctx, req, res, url) {
  const z = zips.get(String(url.searchParams.get('id') || ''));
  if (!z) return sendJson(res, 404, { ok: false, error: '打包任务不存在或已过期' });
  return sendJson(res, 200, {
    ok: true, id: z.id, ready: !!z.ready, error: z.error || '',
    name: z.name, size: z.size, added: z.added, items: z.items,
  });
}

/** 第二步:按 Range 下发已打包好的 ZIP(支持断点续传)。 */
async function handleZipGet(ctx, req, res, url) {
  const z = zips.get(String(url.searchParams.get('id') || ''));
  if (!z) throw new HttpError(404, '打包任务不存在或已过期,请重新打包');
  if (z.error) throw new HttpError(500, `打包失败: ${z.error}`);
  if (!z.ready) throw new HttpError(409, '压缩包还在生成中,请稍候');

  let st;
  try { st = await fsp.stat(z.file); } catch { throw new HttpError(404, '压缩包已被清理,请重新打包'); }
  z.at = Date.now();   // 有下载行为就续期

  logAction({
    action: 'download', ctx, req, path: z.name, ok: true,
    detail: req.headers.range ? `续传 ${z.name}` : `下载 ${z.name}(${fmtSize(st.size)})`,
  });

  const head = {
    'Content-Type': 'application/zip',
    'Content-Disposition': contentDisposition(z.name, false),
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  return sendFileByRange(req, res, z.file, st, head);
}

/**
 * 把一个目录递归加入压缩包,返回加入的文件数。
 * 用 lstat 跳过符号链接/目录联接,防止顺着链接把共享根外的内容打包出去。
 * entry 用于累计文件总数(前端显示进度)。
 */
async function addDirToArchive(archive, dirAbs, zipRoot, entry) {
  let count = 0;
  const walk = async (abs, zipPath) => {
    let names;
    try { names = await fsp.readdir(abs); } catch { return; }
    if (!names.length) {
      archive.append('', { name: zipPath + '/' });   // 保留空目录
      return;
    }
    for (const n of names) {
      if (isThumbName(n)) continue;                 // 低清预览图是内部文件,不打包
      const childAbs = path.join(abs, n);
      const childZip = `${zipPath}/${n}`;
      let st;
      try { st = await fsp.lstat(childAbs); } catch { continue; }
      if (st.isSymbolicLink()) continue;            // 不进链接,防越界
      if (st.isDirectory()) await walk(childAbs, childZip);
      else {
        archive.file(childAbs, { name: childZip });
        count++;
        if (entry) entry.total++;
      }
    }
  };
  await walk(dirAbs, zipRoot);
  return count;
}

/**
 * 解析 Range 请求头,决定要发送的字节区间。
 * 返回 { start, end, status } 或 { invalid: true }(调用方应回 416)。
 * 单独抽出来是为了让「单文件下载」与「打包后的 ZIP 下载」共用同一套断点续传逻辑。
 */
function parseRange(rangeHeader, size) {
  if (!rangeHeader) return { start: 0, end: size - 1, status: 200 };
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(rangeHeader).trim());
  if (!m) return { start: 0, end: size - 1, status: 200 };   // 不认识的 Range:当作整文件
  const [, s, e] = m;
  let start = 0;
  let end = size - 1;
  let status = 200;
  if (s === '' && e !== '') {
    const n = Number(e);
    if (!(n > 0)) return { invalid: true };                  // bytes=-0 / bytes-
    start = Math.max(0, size - n);
    status = 206;
  } else if (s !== '') {
    start = Number(s);
    if (e !== '') end = Math.min(Number(e), size - 1);
    if (start < size && start <= end) status = 206;
    else return { invalid: true };
  } else {
    return { invalid: true };                                // bytes=-
  }
  return { start, end, status };
}

/**
 * 把本地文件按 Range 语义发给客户端(断点续传)。
 * 单文件下载与打包结果下载都走这里,保证行为一致。
 */
function sendFileByRange(req, res, fileAbs, stat, head) {
  const r = parseRange(req.headers.range, stat.size);
  if (r.invalid) {
    res.writeHead(416, { 'Content-Range': `bytes */${stat.size}` });
    res.end();
    return;
  }
  if (r.status === 206) head['Content-Range'] = `bytes ${r.start}-${r.end}/${stat.size}`;
  head['Content-Length'] = r.end - r.start + 1;
  res.writeHead(r.status, head);
  if (req.method === 'HEAD') return res.end();
  const f = fs.createReadStream(fileAbs, { start: r.start, end: r.end });
  pipeline(f, res).catch(() => { f.destroy(); });
}

/**
 * 由 stat 生成 ETag 与 Last-Modified。
 * ETag 用「大小-修改时间(毫秒)」拼成:内容一变(含同名覆盖上传)这个值就变,
 * 所以长缓存也不会看到旧图 —— 浏览器下次请求时会带上 If-None-Match,
 * 服务端比对不通过就返回 304(不传正文),通过才重传。
 */
function validatorsOf(stat) {
  const etag = `"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
  const lastModified = new Date(stat.mtimeMs).toUTCString();
  return { etag, lastModified };
}

/** 判断客户端的条件请求是否可以直接回 304(内容没变)。 */
function isFresh(req, stat) {
  const { etag, lastModified } = validatorsOf(stat);
  const inm = req.headers['if-none-match'];
  if (inm) {
    // 可能形如: "abc", "def" 或 W/"abc"
    const list = String(inm).split(',').map((s) => s.trim().replace(/^W\//, ''));
    if (list.includes(etag) || list.includes('*')) return true;
    return false;   // 明确给了 If-None-Match 但不匹配 → 必须重传
  }
  const ims = req.headers['if-modified-since'];
  if (ims) {
    const t = Date.parse(ims);
    if (!Number.isNaN(t) && Math.floor(stat.mtimeMs / 1000) * 1000 <= t) return true;
  }
  return false;
}

/** 文件下载:支持单段 Range(断点续传)。stat 由调用方传入。 */
function serveFile(req, res, fileAbs, stat) {
  const inline = req.url.startsWith('/raw');
  const type = mimeOf(fileAbs);
  const isExecutable = /(?:^|[/; ])(?:text\/html|application\/xhtml\+xml|image\/svg\+xml)(?=$|[; ])/.test(type)
    || /^text\/javascript/.test(type);
  const disp = contentDisposition(path.basename(fileAbs), inline && !isExecutable);
  // 预览类内容给长缓存 + 强校验:重复预览同一张图时浏览器直接用本地副本,
  // 不再走网络;若文件被同名覆盖,ETag 会变,浏览器自动重新拉新图。
  const cacheable = inline && !isExecutable;
  const { etag, lastModified } = validatorsOf(stat);
  const head = {
    'Content-Type': type,
    'Content-Disposition': disp,
    'Accept-Ranges': 'bytes',
    'Cache-Control': cacheable ? 'private, max-age=86400, must-revalidate' : 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  if (cacheable) {
    head['ETag'] = etag;
    head['Last-Modified'] = lastModified;
  }
  // inline 预览仅在"不可执行内容"时开放;否则一律附件下载,从根上消除 /raw 存储型 XSS/SVG 脚本面。
  if (inline) head['Content-Security-Policy'] = "sandbox; default-src 'none'; style-src 'unsafe-inline'";

  // 协商缓存:内容没变就直接 304,连一个字节的正文都不用传
  if (cacheable && isFresh(req, stat)) {
    res.writeHead(304, { 'ETag': etag, 'Last-Modified': lastModified, 'Cache-Control': head['Cache-Control'] });
    return res.end();
  }

  if (stat.size === 0) {
    // 空文件:无需流,Range 不予理会,返回 200 空体即正确(Content-Range 不适用)。
    head['Content-Length'] = 0;
    res.writeHead(200, head);
    res.end();
    return;
  }
  sendFileByRange(req, res, fileAbs, stat, head);
}

/* ---------------- 分片上传(大文件) ---------------- */

/**
 * 大文件分段上传,解决"传一半断了要重来"的问题:
 *   - 客户端把文件切成若干片,逐个 POST 到 /api/upload/chunk;
 *   - 服务端每片追加写入 .uploading-* 临时文件,并在 .uploading-*.json 记录已收到的字节数;
 *   - 断线/刷新后客户端先 GET /api/upload/status 查询已传进度,从断点续传;
 *   - 全部收齐后 /api/upload/finish 把临时文件原子改名为目标文件。
 * 分片状态放在共享目录内的临时文件里,进程重启后依然可续传。
 */

/** 分片上传的临时文件名(与目标同目录,便于最后 rename 保持同盘原子性)。 */
function chunkPaths(target) {
  const base = `${target}.uploading-chunk`;
  return { part: base, meta: `${base}.json` };
}

async function readChunkMeta(metaPath) {
  try {
    const s = await fsp.readFile(metaPath, 'utf8');
    const m = JSON.parse(s);
    if (!m || typeof m.received !== 'number') return null;
    return m;
  } catch { return null; }
}

/** 查询某个文件在目标目录里已上传的字节数(用于断点续传)。 */
async function handleUploadStatus(ctx, req, res, url) {
  try {
    const dirRel = (url.searchParams.get('dir') || '').replace(/^\/+|\/+$/g, '');
    const name = assertEntryName(url.searchParams.get('name'));
    const size = Number(url.searchParams.get('size')) || 0;
    const { abs } = await resolveExisting(ctx, dirRel);
    const target = path.join(abs, name);
    const { part, meta } = chunkPaths(target);

    const m = await readChunkMeta(meta);
    if (!m) return sendJson(res, 200, { ok: true, received: 0, resumable: false });
    // 元数据与本次请求的文件大小不符(同名但换了文件),视为不可续传
    if (size && m.size && m.size !== size) {
      await fsp.rm(part, { force: true }).catch(() => {});
      await fsp.rm(meta, { force: true }).catch(() => {});
      return sendJson(res, 200, { ok: true, received: 0, resumable: false });
    }
    // 元数据里记录的字节数必须和临时文件实际大小一致,否则以实际为准(取较小值更安全)
    let actual = 0;
    try { actual = (await fsp.stat(part)).size; } catch { actual = 0; }
    const received = Math.min(m.received, actual);
    return sendJson(res, 200, { ok: true, received, resumable: received > 0 });
  } catch (e) {
    if (e instanceof HttpError) return sendJson(res, e.status, { ok: false, error: e.message });
    if (e && e.code === 'ENOENT') return sendJson(res, 404, { ok: false, error: '目录或文件不存在' });
    return sendJson(res, 500, { ok: false, error: `查询上传进度失败: ${e.message}` });
  }
}

/**
 * 接收一个分片。请求体即该片的原始字节。
 * query: dir, name, offset(该片在文件中的起始偏移), size(整个文件大小)
 * 只在 offset 与当前已收字节数吻合时才追加,否则返回 409 让客户端重新对齐。
 */
async function handleUploadChunk(ctx, req, res, url) {
  let dirRel, name, target, part, meta, offset, totalSize;
  try {
    dirRel = (url.searchParams.get('dir') || '').replace(/^\/+|\/+$/g, '');
    name = assertEntryName(url.searchParams.get('name'));
    offset = Number(url.searchParams.get('offset'));
    totalSize = Number(url.searchParams.get('size'));
    if (!Number.isFinite(offset) || offset < 0) throw new HttpError(400, '缺少或非法的 offset');

    const { abs } = await resolveExisting(ctx, dirRel);
    const stDir = await fsp.stat(abs).catch(() => null);
    if (!stDir || !stDir.isDirectory()) throw new HttpError(404, '上传目标目录不存在');
    target = path.join(abs, name);
    ({ part, meta } = chunkPaths(target));

    // 同名目录不允许被文件覆盖
    const existed = await fsp.lstat(target).then((s) => s).catch(() => null);
    if (existed && existed.isDirectory()) throw new HttpError(409, '同名项是一个已存在的目录,不能覆盖');
    if (!ALLOW_OVERWRITE && existed) throw new HttpError(409, '同名文件已存在(allowOverwrite=false)');

    // 总量上限(按整个文件算,而不是单片)
    if (MAX_UPLOAD_BYTES > 0 && totalSize > MAX_UPLOAD_BYTES) {
      throw new HttpError(413, `超出单文件大小上限 ${CONFIG.maxUploadMB}MB`);
    }
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    return sendJson(res, status, { ok: false, error: e.message });
  }

  try {
    // 校验当前进度:不吻合就告诉客户端应该从哪继续(客户端据此回退重传该片)
    let current = 0;
    try { current = (await fsp.stat(part)).size; } catch { current = 0; }
    const m = await readChunkMeta(meta);
    if (m && typeof m.received === 'number' && m.received <= current) current = m.received;
    if (m && m.size && totalSize && m.size !== totalSize) current = 0;   // 换了文件,重头来

    if (offset !== current) {
      return sendJson(res, 409, { ok: false, error: '分片偏移不匹配', received: current });
    }

    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(part, { flags: offset === 0 ? 'w' : 'a' });
      let err = null;
      const fail = (e) => { if (!err) err = e; };
      req.on('error', fail);
      req.on('aborted', () => fail(new Error('客户端中断')));
      out.on('error', fail);
      pipeline(req, out).catch(fail);
      out.on('close', () => (err ? reject(err) : resolve()));
    });

    const written = (await fsp.stat(part)).size;
    await fsp.writeFile(meta, JSON.stringify({
      name, size: totalSize || written, received: written, updatedAt: Date.now(),
    }), 'utf8');
    return sendJson(res, 200, { ok: true, received: written, done: totalSize > 0 && written >= totalSize });
  } catch (err) {
    return sendJson(res, 500, { ok: false, error: `分片写入失败: ${err.message || err}` });
  }
}

/** 收齐所有分片后,把临时文件原子改名为目标文件。 */
async function handleUploadFinish(ctx, req, res, url, body) {
  try {
    const dirRel = (url.searchParams.get('dir') || '').replace(/^\/+|\/+$/g, '');
    const name = assertEntryName(url.searchParams.get('name'));
    const totalSize = Number(url.searchParams.get('size'));
    const { abs } = await resolveExisting(ctx, dirRel);
    const target = path.join(abs, name);
    const { part, meta } = chunkPaths(target);

    const st = await fsp.stat(part).catch(() => null);
    if (!st) return sendJson(res, 404, { ok: false, error: '没有找到已上传的分片数据' });
    if (Number.isFinite(totalSize) && totalSize > 0 && st.size !== totalSize) {
      return sendJson(res, 409, {
        ok: false, error: `分片不完整(${st.size}/${totalSize} 字节)`, received: st.size,
      });
    }
    const existed = await fsp.lstat(target).then((s) => s).catch(() => null);
    if (existed && existed.isDirectory()) {
      return sendJson(res, 409, { ok: false, error: '同名项是一个已存在的目录,不能覆盖' });
    }
    await fsp.rename(part, target);
    await fsp.rm(meta, { force: true }).catch(() => {});
    const fin = await fsp.stat(target);
    publishChange('up', mainRelOf(ctx, path.posix.join(dirRel, name)));
    logAction({ action: 'upload', ctx, req, path: path.posix.join(dirRel, name), ok: true, detail: fmtSize(fin.size) });

    // 图片/视频:顺带生成缩略图或封面(失败不影响上传结果)
    if (isImageName(name) || isVideoName(name)) {
      generateThumb(target).catch(() => {});
    }
    return sendJson(res, 200, { ok: true, size: fin.size, path: dirRel ? `${dirRel}/${name}` : name });
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: `收尾失败: ${e.message || e}` });
  }
}

/** 上传:请求体为原始文件字节,name 与目标目录在 query 中。 */
async function handleUpload(ctx, req, res, url) {
  const dirRel = (url.searchParams.get('dir') || '').replace(/^\/+|\/+$/g, '');
  const name = assertEntryName(url.searchParams.get('name'));
  const { abs } = await resolveExisting(ctx, dirRel);
  const stDir = await fsp.stat(abs).catch(() => null);
  if (!stDir) return sendJson(res, 404, { ok: false, error: '上传目标目录不存在' });
  if (!stDir.isDirectory()) {
    return sendJson(res, 409, { ok: false, error: '上传目标同名项是一个文件而非文件夹,无法写入其中' });
  }
  const target = path.join(abs, name);

  if (!ALLOW_OVERWRITE && fs.existsSync(target)) {
    return sendJson(res, 409, { ok: false, error: '同名文件已存在(allowOverwrite=false)' });
  }

  const cl = Number(req.headers['content-length']);
  if (MAX_UPLOAD_BYTES > 0 && cl > MAX_UPLOAD_BYTES) {
    return sendJson(res, 413, { ok: false, error: `超出单文件大小上限 ${CONFIG.maxUploadMB}MB` });
  }

  const tmp = `${target}.uploading-${process.pid}-${Date.now()}`;
  let received = 0;
  const out = fs.createWriteStream(tmp, { flags: 'wx' });

  try {
    // 等待请求体完整写入临时文件。错误统一在 out close 时结算:
    // error/'aborted' 事件、断流、pipeline 失败先记录到 err,再于 close 统一 reject,
    // 避免 close 先于 error 触发而把“半截文件”误判为成功。
    await new Promise((resolve, reject) => {
      let err = null;
      let limitError = null;
      const fail = (e) => { if (!err) err = e; };
      req.on('data', (chunk) => {
        received += chunk.length;
        if (MAX_UPLOAD_BYTES > 0 && received > MAX_UPLOAD_BYTES && !limitError) {
          limitError = new HttpError(413, `超出单文件大小上限 ${CONFIG.maxUploadMB}MB`);
          req.destroy();
        }
      });
      req.on('error', fail);
      req.on('aborted', () => fail(new Error('客户端中断上传')));
      out.on('error', fail);
      pipeline(req, out).catch(fail); // 正常完成时 promise 无副作用,close 结算
      out.on('close', () => {
        if (limitError) return reject(limitError);
        if (err) return reject(err);
        resolve();
      });
    });
    const existed = await fsp.lstat(target).then((s) => s).catch(() => null);
    if (existed && existed.isDirectory()) {
      // 同名目录:即使 allowOverwrite=true 也不允许用文件覆盖目录
      sendJson(res, 409, { ok: false, error: '同名项是一个已存在的目录,不能覆盖' });
      return;
    }
    await fsp.rename(tmp, target);
    const st = await fsp.stat(target);
    publishChange('up', mainRelOf(ctx, path.posix.join(dirRel, name)));
    logAction({ action: 'upload', ctx, req, path: path.posix.join(dirRel, name), ok: true, detail: fmtSize(st.size) });
    // 图片/视频:顺带生成缩略图或封面(失败不影响上传结果)
    if (isImageName(name) || isVideoName(name)) generateThumb(target).catch(() => {});
    sendJson(res, 200, { ok: true, size: st.size, path: dirRel ? `${dirRel}/${name}` : name });
  } catch (err) {
    out.destroy();
    await fsp.rm(tmp, { force: true }).catch(() => {});
    if (res.headersSent) return;
    if (err instanceof HttpError) return sendJson(res, err.status, { ok: false, error: err.message });
    if (err && (err.code === 'EEXIST' || err.code === 'EISDIR' || err.code === 'ENOTEMPTY')) {
      return sendJson(res, 409, { ok: false, error: '同名路径已存在且不为可覆盖文件' });
    }
    sendJson(res, 500, { ok: false, error: `上传失败: ${err.message || err}` });
  }
}

/**
 * 解析"共享根内一条相对目录路径"并保证它真实存在(允许自动递归创建缺失的目录层)。
 * - 路径只含各层目录名,组成不含 .. / 空段 / 反斜杠;
 * - 先校验"已存在的最近祖先"落在共享目录内(防符号链接祖先逃逸),再对缺失层 mkdir;
 * - 返回位于共享目录内的真实目录绝对路径。用于 mkdir、目录上传时创建目标子目录链。
 */
async function resolveDirExistent(ctx, relStr) {
  if (typeof relStr !== 'string' || relStr.includes('\0')) throw new HttpError(400, '非法路径参数');
  let rel = relStr.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (rel === '') {
    const real = await fsp.realpath(ctx.root);
    if (!isInside(ctx.rootReal, real)) throw new HttpError(403, '拒绝访问共享目录之外的位置');
    return real;
  }
  const parts = rel.split('/');
  for (const p of parts) assertRelSegment(p);

  // 逐层找到第一个尚不存在的层 => 其上一个已存在祖先用于越界 realpath 校验
  let probe = ctx.root;
  const missing = [];
  for (const p of parts) {
    probe = path.join(probe, p);
    if (missing.length === 0 && fs.existsSync(probe)) continue;
    missing.push(probe);
  }
  if (fs.existsSync(probe)) {
    const real = await fsp.realpath(probe);
    if (!isInside(ctx.rootReal, real)) throw new HttpError(403, '拒绝访问共享目录之外的位置');
    const st = await fsp.stat(real).catch(() => null);
    if (st && !st.isDirectory()) {
      throw new HttpError(409, '同名项是一个文件而非文件夹:无法在此创建/进入目录');
    }
    return real;
  }
  // 部分链不存在:校验最近已存在的祖先是真实目录且不越界
  let base = path.dirname(missing[0]);
  while (!fs.existsSync(base)) { const up = path.dirname(base); if (up === base) break; base = up; }
  const realBase = await fsp.realpath(base);
  if (!isInside(ctx.rootReal, realBase)) throw new HttpError(403, '拒绝访问共享目录之外的位置');
  const stb = await fsp.stat(realBase).catch(() => null);
  if (stb && !stb.isDirectory()) throw new HttpError(409, '同名项是一个文件:无法作为目录构建路径');
  await fsp.mkdir(missing[missing.length - 1], { recursive: true });
  const real = await fsp.realpath(missing[missing.length - 1]);
  if (!isInside(ctx.rootReal, real)) { await clearOnlyMissing(); throw new HttpError(403, '拒绝访问共享目录之外的位置'); }
  return real;

  async function clearOnlyMissing() {
    // 若刚 mkdir 的部分泄出共享根(极端符号链接后置情形),删除新建
    for (let i = missing.length - 1; i >= 0; i--) { try { await fsp.rmdir(missing[i]); } catch { return; } }
  }
}

/** 删除:path 指向共享根内的文件或目录(不含根本身),永久删除。 */
async function handleDelete(ctx, req, res, url) {
  const rel = (url.searchParams.get('path') || '').replace(/\\/g, '/').replace(/^\/+/, '');
  if (rel === '') return sendJson(res, 400, { ok: false, error: '不能删除共享目录根' });
  const { abs } = await resolveExisting(ctx, rel);
  if (abs === ctx.rootReal) return sendJson(res, 400, { ok: false, error: '不能删除共享目录根' });
  try {
    await fsp.rm(abs, { recursive: true, force: false }); // force:false => 不存在时报错, 避免静默吞
    // 同步清掉该文件的低清预览图,避免留下孤儿文件(目录被删时其内部缩略图已随之删除)
    await fsp.rm(thumbPathOf(abs), { force: true }).catch(() => {});
  } catch (e) {
    if (e && e.code === 'ENOENT') return sendJson(res, 404, { ok: false, error: '文件或目录不存在' });
    if (e && e.code === 'EACCES' || e && e.code === 'EPERM') return sendJson(res, 403, { ok: false, error: '没有删除权限或目标被占用' });
    return sendJson(res, 500, { ok: false, error: `删除失败: ${e.message || e}` });
  }
  publishChange('del', mainRelOf(ctx, rel));
  logAction({ action: 'delete', ctx, req, path: rel, ok: true });
  sendJson(res, 200, { ok: true, removed: rel });
}

/** 重命名:path 指向共享根内现有文件/目录,to 为新名称(不含路径分隔)。 */
async function handleRename(ctx, req, res, url) {
  const rel = (url.searchParams.get('path') || '').replace(/\\/g, '/').replace(/^\/+/, '');
  const to = url.searchParams.get('to');
  if (rel === '') return sendJson(res, 400, { ok: false, error: '不能重命名共享目录根' });
  const newName = assertEntryName(to);
  const { abs } = await resolveExisting(ctx, rel);
  const newAbs = path.join(path.dirname(abs), newName);
  if (newAbs === abs) return sendJson(res, 200, { ok: true, renamed: rel, to: newName });
  try {
    await fsp.access(newAbs);
    return sendJson(res, 409, { ok: false, error: '目标名称已存在' });
  } catch (e) { /* 目标不存在 */ }
  try {
    await fsp.rename(abs, newAbs);
  } catch (e) {
    if (e && (e.code === 'ENOENT')) return sendJson(res, 404, { ok: false, error: '要重命名的项不存在' });
    if (e && (e.code === 'EACCES' || e.code === 'EPERM')) return sendJson(res, 403, { ok: false, error: '没有重命名权限' });
    return sendJson(res, 500, { ok: false, error: `重命名失败: ${e.message || e}` });
  }
  // 图片的缩略图随原名走,重命名时一并改名;否则新名字会失去已有的低清预览
  // (即便不改名也无害:serveThumb 发现缩略图缺失会按需重新生成)
  if (isImageName(abs)) {
    const oldThumb = thumbPathOf(abs);
    const newThumb = thumbPathOf(newAbs);
    await fsp.rename(oldThumb, newThumb).catch(() => {});
  }
  // 计算新 rel 便于前端跳转
  const parent = rel.split('/').slice(0, -1).join('/');
  const newRel = parent ? `${parent}/${newName}` : newName;
  publishChange('del', mainRelOf(ctx, rel));
  publishChange('up', mainRelOf(ctx, newRel));
  logAction({ action: 'rename', ctx, req, path: rel, ok: true, detail: `→ ${newName}` });
  sendJson(res, 200, { ok: true, renamed: rel, to: newName, path: newRel });
}

/** 建目录:path 为共享根内相对目录(可含多层,不存在则创建)。 */
async function handleMkdir(ctx, req, res, url) {
  const rel = (url.searchParams.get('path') || '').replace(/\\/g, '/').replace(/^\/+/, '');
  try { await resolveDirExistent(ctx, rel); }
  catch (e) {
    if (e instanceof HttpError) return sendJson(res, e.status, { ok: false, error: e.message });
    return sendJson(res, 500, { ok: false, error: `创建目录失败: ${e.message || e}` });
  }
  if (rel) publishChange('up', mainRelOf(ctx, rel));
  logAction({ action: 'mkdir', ctx, req, path: rel, ok: true });
  sendJson(res, 200, { ok: true, path: rel });
}

/* ---------------- 终端彩色输出 ---------------- */

/**
 * 终端配色。要点:
 *   - 只有在真正连到终端(TTY)时才上色;重定向到文件、被管道接走时自动关闭,
 *     这样日志文件里不会混进 ANSI 转义序列(grep/notepad 看着干净)。
 *   - NO_COLOR / FORCE_COLOR 环境变量可覆盖,遵循社区约定。
 *   - Windows 10+ 的终端默认支持 ANSI,旧版 conhost 若显示异常可设 NO_COLOR=1。
 */
const COLOR_ENABLED = (() => {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR === '1' || process.env.FORCE_COLOR === 'true') return true;
  if (process.env.FORCE_COLOR === '0' || process.env.FORCE_COLOR === 'false') return false;
  return !!(process.stdout && process.stdout.isTTY);
})();

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m',
  gray: '\x1b[90m', brightRed: '\x1b[91m', brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m', brightCyan: '\x1b[96m',
};
/** 上色(未启用颜色时原样返回)。 */
function paint(text, ...codes) {
  if (!COLOR_ENABLED || !codes.length) return String(text);
  return codes.join('') + String(text) + C.reset;
}

/**
 * 各类行为的显示风格:级别标签 + 标签底色 + 正文颜色。
 * 级别便于 grep(/^\[ERROR\]/),颜色便于一眼扫出写操作与异常。
 */
const ACTION_STYLE = {
  // 写操作(会改动磁盘,最需要被注意到)
  upload:   { tag: 'WRITE',  tagColor: C.bold + C.green,  text: C.green },
  delete:   { tag: 'WRITE',  tagColor: C.bold + C.red,    text: C.red },
  rename:   { tag: 'WRITE',  tagColor: C.bold + C.yellow, text: C.yellow },
  mkdir:    { tag: 'WRITE',  tagColor: C.bold + C.green,  text: C.green },
  // 读操作
  browse:   { tag: 'BROWSE', tagColor: C.gray,             text: C.gray },
  download: { tag: 'READ',   tagColor: C.bold + C.cyan,   text: C.cyan },
  preview:  { tag: 'READ',   tagColor: C.cyan,            text: C.cyan },
  // 分享管理
  shareAdd:    { tag: 'SHARE', tagColor: C.bold + C.magenta, text: C.magenta },
  shareDel:    { tag: 'SHARE', tagColor: C.bold + C.magenta, text: C.magenta },
  sharePwd:    { tag: 'SHARE', tagColor: C.magenta,          text: C.magenta },
  sharePort:   { tag: 'SHARE', tagColor: C.magenta,          text: C.magenta },
  shareWebdav: { tag: 'SHARE', tagColor: C.magenta,          text: C.magenta },
  rootPwd:     { tag: 'SHARE', tagColor: C.magenta,          text: C.magenta },
  // 异常 / 拒绝
  deny:  { tag: 'DENY',  tagColor: C.bold + C.brightRed,   text: C.brightRed },
  error: { tag: 'ERROR', tagColor: C.bold + C.brightRed,   text: C.brightRed },
};
const DEFAULT_STYLE = { tag: 'INFO', tagColor: C.bold + C.blue, text: C.reset };

/** 统一格式的启动/提示输出:带一个小标签,便于和操作日志区分。 */
function banner(text) { console.log(paint(text, C.dim)); }
function note(label, text) { console.log(`  ${paint(label, C.bold + C.blue)} ${text}`); }
function warnLine(text) { console.log(paint('  [WARN] ', C.bold + C.brightYellow) + text); }
function errorLine(text) { console.error(paint('  [ERROR] ', C.bold + C.brightRed) + text); }

/* ---------------- 操作日志 ---------------- */

/**
 * 记录“谁、在哪里、用什么设备、做了什么、结果如何”。
 * 日志级别(server.logLevel / config.json 的 logLevel):
 *   quiet   仅记录写操作(上传/删除/重命名/建目录)与分享管理
 *   normal  默认:写操作 + 目录浏览/下载/预览
 *   verbose 额外记录每个请求(含被拒绝的)与静态页
 */

const LOG_LEVELS = { quiet: 0, normal: 1, verbose: 2 };
const LOG_LABEL = {
  browse: '浏览目录', download: '下载文件', preview: '预览文件', upload: '上传文件',
  delete: '删除', rename: '重命名', mkdir: '新建目录',
  shareAdd: '创建单独分享', shareDel: '取消单独分享', sharePwd: '修改分享口令', sharePort: '修改分享端口',
  shareWebdav: 'WebDAV 开关',
  sharePick: '选择本机文件夹',
  rootPwd: '修改访问密码',
  deny: '拒绝访问', error: '服务异常',
};
// 这些动作属于“写操作”,在 quiet 级别也记录
const WRITE_ACTIONS = new Set(['upload', 'delete', 'rename', 'mkdir', 'shareAdd', 'shareDel', 'sharePwd', 'sharePort', 'shareWebdav', 'rootPwd']);
// 这些动作只在 verbose 级别记录(高频且信息量低)
// 这些动作只在 verbose 级别记录(信息量大、正常运行时噪声多)
// 注意:deny(拒绝访问)不在此列 —— 它是安全信号,normal 级别也应当能看到,
//       否则“有人在猜口令 / 试探路径”这类情况会被默认静音。
const VERBOSE_ONLY = new Set(['error']);

const hostnameCache = new Map(); // ip -> hostname(反向解析结果,失败缓存空串避免反复超时)
let logSeq = 0;
const recentLogs = []; // 内存中的最近日志,供网页端查看
const RECENT_LOG_MAX = 300;

function shouldLog(action) {
  const lv = LOG_LEVELS[LOG_LEVEL] ?? 1;
  if (lv >= 2) return true;
  if (WRITE_ACTIONS.has(action)) return true;      // quiet 也记录写操作
  if (action === 'deny') return lv >= 1;           // normal 及以上记录拒绝访问
  if (lv >= 1 && !VERBOSE_ONLY.has(action)) return true;
  return false;
}

/** 反向解析客户端 IP 的主机名(仅用于日志展示;失败则留空,不阻塞请求)。 */
function lookupHost(ip) {
  if (hostnameCache.has(ip)) return hostnameCache.get(ip);
  hostnameCache.set(ip, ''); // 先占位,防止同一请求期间重复触发
  const dns = require('node:dns');
  dns.reverse(ip, (err, names) => {
    hostnameCache.set(ip, (!err && names && names[0]) ? names[0] : '');
  });
  return '';
}

/** 从 User-Agent 里提取一个便于阅读的设备/浏览器描述。 */
function describeUA(ua) {
  if (!ua) return '未知客户端';
  const s = String(ua);
  let os = '';
  if (/Windows NT 10/.test(s)) os = 'Windows 10/11';
  else if (/Windows NT/.test(s)) os = 'Windows';
  else if (/Android/.test(s)) os = 'Android';
  else if (/iPhone|iPad|iPod/.test(s)) os = 'iOS';
  else if (/Mac OS X/.test(s)) os = 'macOS';
  else if (/Linux/.test(s)) os = 'Linux';
  let br = '';
  if (/Edg\//.test(s)) br = 'Edge';
  else if (/OPR\/|Opera/.test(s)) br = 'Opera';
  else if (/Chrome\//.test(s)) br = 'Chrome';
  else if (/Firefox\//.test(s)) br = 'Firefox';
  else if (/Safari\//.test(s)) br = 'Safari';
  else if (/curl\//i.test(s)) br = 'curl';
  else if (/python|requests/i.test(s)) br = 'Python';
  const out = [os, br].filter(Boolean).join(' · ');
  return out || s.slice(0, 40);
}

const pad2 = (n) => String(n).padStart(2, '0');
function stamp(d = new Date()) {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} `
    + `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

/**
 * 写一条操作日志。
 * info = { action, path, detail, ok, status, req, ctx }
 * ctx 为当前监听器作用域(决定“在哪个共享里”),req 用于取 IP / UA。
 */
function logAction(info) {
  const { action, ctx } = info;
  if (!shouldLog(action)) return;

  const req = info.req;
  const ip = req ? clientIP(req) : '';
  const host = ip ? lookupHost(ip) : '';
  const who = host && host !== ip ? `${ip}(${host})` : ip || '本机';
  const device = req ? describeUA(req.headers['user-agent']) : '';
  const where = ctx
    ? (ctx.kind === 'main'
        // 主共享带访问密码时,标注这条日志是“凭密码从局域网进来的”,便于事后核对
        ? `主共享:${ctx.port}${ctx.viaRootPwd ? '(凭访问密码)' : ''}`
        : `单独分享「${ctx.title.replace(/ · 单独分享$/, '')}」:${ctx.port}`)
    : '-';
  const target = info.path ? ` /${String(info.path).replace(/^\/+/, '')}` : ' /';
  const ok = info.ok !== false;
  const style = ACTION_STYLE[action] || DEFAULT_STYLE;

  // 彩色行:时间(灰) 级别标签(按行为配色) 动作(按行为配色) 其余信息(常规)
  // ok=false 时整个正文标红,便于在刷屏里一眼看到失败。
  // 方括号便于 grep(如 /^\[DENY\]/、/^\[ERROR\]/),也方便按级别过滤日志。
  const time = paint(`[${stamp()}]`, C.gray);
  const tag = paint(`[${style.tag}]`, style.tagColor);
  const actionTxt = paint(LOG_LABEL[action] || action, style.tagColor);
  const stateTxt = ok ? paint('成功', C.green) : paint('失败', C.bold + C.brightRed);
  const bodyColor = ok ? style.text : C.brightRed;
  const body = paint(
    `谁: ${who} | 设备: ${device || '未知'} | 位置: ${where}${target}`
    + (info.detail ? ` | ${info.detail}` : '')
    + (!ok && info.status ? ` | HTTP ${info.status}` : ''),
    bodyColor
  );

  console.log(`${time} ${tag} ${actionTxt} ${stateTxt} ${body}`);

  recentLogs.push({
    seq: ++logSeq,
    ts: Date.now(),
    action,
    actionLabel: LOG_LABEL[action] || action,
    ok,
    status: info.status || 0,
    ip,
    host,
    device,
    where,
    path: info.path || '',
    detail: info.detail || '',
  });
  if (recentLogs.length > RECENT_LOG_MAX) recentLogs.splice(0, recentLogs.length - RECENT_LOG_MAX);
}

/** 取客户端 IP(已处理 IPv4-mapped IPv6 与回环写法)。 */
function clientIP(req) {
  let ip = (req.socket && req.socket.remoteAddress) || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);   // IPv4-mapped
  if (ip === '::1') ip = '127.0.0.1';               // IPv6 回环归一
  return ip;
}

/* ---------------- 变更广播(实时静默同步) ---------------- */

/**
 * 共享目录发生变更时,向所有已连接的浏览器推送一条 SSE 事件,收到方静默重载
 * 当前目录,从而实现“这边改了、那边不用刷新页面就同步”。
 * - 由本服务自身的写接口(上传/删除/重命名/建目录)主动 publish,即时且准确;
 * - 另有 fs.watch 兜底,覆盖直接在资源管理器/其他程序里改动共享目录的情况,
 *   以及上传过程中的中间态(先防抖,等 500ms 无新事件再广播)。
 */

const sseClients = new Set(); // 元素为 { res, scope } —— scope 区分主共享与各单独分享
const HEARTBEAT_MS = 25000;
const WATCH_DEBOUNCE_MS = 500;

function sseSend(res, event, data) {
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  } catch {
    try { res.end(); } catch { /* 已断开 */ }
    for (const c of sseClients) if (c.res === res) sseClients.delete(c);
  }
}

/**
 * 广播一次变更。rel 为「主共享根内」的相对路径(文件或目录,使用 / 分隔),
 * 这样主共享与所有单独分享端口都能按各自作用域推导出是否与自己相关。
 * scope 为发起变更的作用域('main' 或 shareId);单独分享端口内的变更需要
 * 换算成主共享路径后再广播,因此调用方传入的 rel 应已是主共享内的路径。
 */
let lastPublish = { key: '', at: 0 };
/**
 * 判断某条 fs 事件是否“只与缩略图有关”,从而不该触发前端刷新。
 * Windows 上 fs.watch 可能只报出所属目录(如 "照片"),此时 p 本身不是缩略图文件名,
 * 所以再往下一层看:该目录里所有的 *.thumb.jpg 都是被忽略的,只有真文件变化才广播。
 * 这里用“目录内是否全是缩略图”无法判定,因此采取保守策略:
 * 若 p 是目录且我们最近刚生成过缩略图,则视为缩略图噪声,跳过。
 */
let lastThumbAt = 0;
function markThumbWrite() { lastThumbAt = Date.now(); }
function isThumbNoise(p) {
  if (isThumbName(p)) return true;
  // 目录级事件:如果 1.5 秒内刚写过缩略图,很可能是这次写入引发的,跳过
  return Date.now() - lastThumbAt < 1500;
}

function publishChange(kind, rel) {
  if (sseClients.size === 0) return;
  const relNorm = String(rel || '').replace(/\\/g, '/');
  // 缩略图写入不该被当成“共享内容变化”:否则每加载一张缩略图就会让列表整体重刷,
  // 表现为“取到一张缩略图、所有缩略图都跟着闪一遍”。
  if (kind === 'fs' && isThumbNoise(relNorm)) return;
  const parent = path.posix.dirname(relNorm).replace(/^\.$/, '');
  const key = (kind === 'fs' ? 'fs:' : 'api:') + relNorm;
  // 本服务的写接口已广播过,紧随其后的 fs.watch 回调是同一件事:去重,避免客户端连刷两次
  if (kind === 'fs') {
    const dupApi = lastPublish.key === 'api:' + relNorm && Date.now() - lastPublish.at < 1500;
    const dupParent = lastPublish.key.startsWith('api:') && (lastPublish.key.slice(4) === parent || parent === '')
      && Date.now() - lastPublish.at < 1500;
    if (dupApi || dupParent) return;
  } else if (lastPublish.key === key && Date.now() - lastPublish.at < 50) {
    return; // 同一路径的重复写接口广播(如重命名前的同名操作)
  }
  lastPublish = { key, at: Date.now() };
  const payload = { type: kind, path: relNorm, parent, ts: Date.now() };
  for (const client of [...sseClients]) {
    // 每个客户端只关心自己作用域内的变更:单独分享端口收到的是“去掉前缀后的相对路径”
    const view = viewFor(client.scope, relNorm);
    if (view === null) continue;
    sseSend(client.res, 'change', { ...payload, path: view.path, parent: view.parent });
  }
}

/**
 * 把「主共享内的路径」换算到某个作用域下的相对路径。
 * 返回 null 表示该变更不在这个客户端的视野内(不必通知)。
 * - 主共享:原样;
 * - 单独分享(scope 为 shareId):只有当变更落在该分享的子树内才通知,并去掉前缀。
 */
function viewFor(scope, mainRel) {
  if (scope === 'main') return { path: mainRel, parent: path.posix.dirname(mainRel).replace(/^\.$/, '') };
  const sh = shares.get(scope);
  if (!sh) return null;
  const prefix = sh.rel;
  if (mainRel === prefix) return { path: '', parent: '' };
  if (!mainRel.startsWith(prefix + '/')) return null;
  const inner = mainRel.slice(prefix.length + 1);
  return { path: inner, parent: path.posix.dirname(inner).replace(/^\.$/, '') };
}

/** fs.watch 兜底:合并短时间内的连续事件(如一次上传会触发多次)后再广播一次。 */
let watchTimer = null;
let watchPath = '';
function watchDir() {
  try {
    return fs.watch(SHARE_ROOT, { recursive: true, persistent: false }, (eventType, filename) => {
      if (filename) watchPath = String(filename).replace(/\\/g, '/');
      if (watchTimer) return;
      watchTimer = setTimeout(() => {
        watchTimer = null;
        const p = watchPath;
        watchPath = '';
        // Windows 上 fs.watch 对深层改动常只报出所属目录,故用最新事件路径(可能为空)
        if (p.includes('.uploading-')) return; // 上传中间态,由写接口收尾时广播
        // 缩略图是本服务按需生成的内部文件:它的写入不应触发“共享内容变化”广播,
        // 否则前端每加载一张缩略图都会把整个目录重新渲染一遍(列表全部闪烁重刷)。
        if (isThumbName(p)) return;
        publishChange('fs', p);
      }, WATCH_DEBOUNCE_MS);
    });
  } catch {
    return null; // 某些文件系统不支持递归监视:退化为只靠写接口广播
  }
}

function handleEvents(ctx, req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': connected\n\n');
  const client = { res, scope: ctx.kind === 'main' ? 'main' : ctx.shareId };
  sseClients.add(client);
  const beat = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { /* 忽略 */ }
  }, HEARTBEAT_MS);
  req.on('close', () => { clearInterval(beat); sseClients.delete(client); });
}

/* ---------------- 低清预览图(可选依赖 sharp) ---------------- */

/**
 * 生成低清预览图:装了 sharp 就用来压一张小图存成 "<原文件名>.thumb.jpg",
 * 前端预览时先秒开这张低清图,同时后台继续加载高清原图。
 * 没有 sharp 时本模块静默跳过——服务功能不受影响,只是预览直接加载原图。
 */
let sharp = null;
let sharpLoadTried = false;
function loadSharp() {
  if (sharpLoadTried) return sharp;
  sharpLoadTried = true;
  try {
    sharp = require('sharp');
    note('预览压缩  ', paint('已启用', C.green) + paint(' (sharp ' + (sharp.versions && sharp.versions.sharp || '') + ')', C.dim));
  } catch {
    sharp = null;
    note('预览压缩  ', paint('未启用', C.yellow) + paint(' 未安装 sharp,将直接加载原图(如需低清预览请执行 npm install)', C.dim));
  }
  // 顺带报告视频封面能力(ffmpeg 是可选的)
  const ff = findFfmpeg();
  if (ff) note('视频封面  ', paint('已启用', C.green) + paint(' (ffmpeg)', C.dim));
  else note('视频封面  ', paint('未启用', C.yellow) + paint(' 未找到 ffmpeg,视频只显示图标(装好 ffmpeg 并加入 PATH 即可)', C.dim));
  return sharp;
}
function thumbPathOf(fileAbs) { return fileAbs + THUMB_SUFFIX; }
function isImageName(name) {
  const ext = (String(name).match(/\.([^.]+)$/) || [])[1] || '';
  return ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tiff', 'avif', 'svg'].includes(ext.toLowerCase());
}

/** 常见视频格式:这些文件用 ffmpeg 抽一帧做封面。 */
function isVideoName(name) {
  const ext = (String(name).match(/\.([^.]+)$/) || [])[1] || '';
  return ['mp4', 'm4v', 'mov', 'mkv', 'webm', 'avi', 'wmv', 'flv', 'ts', 'm2ts', 'mpg', 'mpeg', '3gp', 'rmvb', 'rm'].includes(ext.toLowerCase());
}

/** ffmpeg / ffprobe 是否可用(启动时探测一次)。 */
let ffmpegPath = '';
let ffmpegProbed = false;
function findFfmpeg() {
  if (ffmpegProbed) return ffmpegPath;
  ffmpegProbed = true;
  const { execFileSync } = require('node:child_process');
  const candidates = [
    process.env.FFMPEG_PATH,
    'ffmpeg',                                   // PATH 里
    'D:/ffmpeg-2026-07-20-git-c23123630e-essentials_build/bin/ffmpeg.exe',
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      execFileSync(c, ['-version'], { stdio: 'ignore', timeout: 5000 });
      ffmpegPath = c;
      return ffmpegPath;
    } catch { /* 试下一个 */ }
  }
  // 再试着在项目目录/常见目录里找一下
  try {
    const dirs = ['D:/', 'C:/', 'D:/tools'];
    for (const d of dirs) {
      let names;
      try { names = fs.readdirSync(d); } catch { continue; }
      const hit = names.find((n) => /^ffmpeg/i.test(n));
      if (!hit) continue;
      const exe = path.join(d, hit, 'bin', process.platform === 'win32' ? 'ffmpeg.exe' : 'ffmpeg');
      if (fs.existsSync(exe)) { ffmpegPath = exe; return ffmpegPath; }
    }
  } catch { /* 忽略 */ }
  ffmpegPath = '';
  return ffmpegPath;
}

/** 为图片或视频生成低清缩略图(失败只记录,不影响上传结果)。 */
async function generateThumb(fileAbs) {
  const dest = thumbPathOf(fileAbs);
  const isVid = isVideoName(fileAbs);
  if (!isVid && !isImageName(fileAbs)) return false;

  try {
    // 已有且比原文件新就跳过,避免重复生成
    const [st, dt] = await Promise.all([
      fsp.stat(fileAbs).catch(() => null),
      fsp.stat(dest).catch(() => null),
    ]);
    if (!st) return false;
    if (dt && dt.mtimeMs >= st.mtimeMs) return true;

    // 标记“正在写缩略图”:让 fs.watch 的后续事件被识别为内部噪声,不触发前端刷新
    markThumbWrite();

    if (isVid) {
      // 视频:用 ffmpeg 抽一帧当封面。
      // 取第 1 秒(而不是第 0 帧),因为很多视频开头是黑屏/纯色,取 1 秒更容易得到有内容的画面;
      // 若视频不足 1 秒则自动回退到第一帧。
      const ok = await extractVideoFrame(fileAbs, dest);
      markThumbWrite();
      return ok;
    }

    const s = loadSharp();
    if (!s) return false;
    await s(fileAbs, { failOn: 'none' })
      .rotate()                                   // 依 EXIF 方向摆正
      // 预览图长边压到 960px:足够看清画面,又能显著小于原图(相机原图常见 4000px+)
      .resize({ width: 960, height: 960, fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 68, progressive: true, mozjpeg: true })
      .toFile(dest);
    markThumbWrite();
    return true;
  } catch {
    return false;                                 // 损坏图片/格式不支持等:静默跳过
  }
}

/**
 * 用 ffmpeg 从视频里抽一帧存成 JPEG 封面。
 * 抽帧策略:先试第 1 秒;失败(视频过短/定位不到)再回退到第一帧。
 */
function extractVideoFrame(fileAbs, dest) {
  return new Promise((resolve) => {
    const exe = findFfmpeg();
    if (!exe) return resolve(false);              // 没装 ffmpeg:静默跳过,前端会显示占位图标
    const { execFile } = require('node:child_process');
    const tmp = dest + '.tmp.jpg';
    const args = (seek) => {
      const a = ['-hide_banner', '-loglevel', 'error', '-y'];
      if (seek) a.push('-ss', seek);
      a.push('-i', fileAbs, '-frames:v', '1', '-vf',
        // 等比缩放到长边 960,与图片缩略图保持一致
        "scale='min(960,iw)':'min(960,ih)':force_original_aspect_ratio=decrease",
        '-q:v', '4', tmp);
      return a;
    };
    const run = (seek, onFail) => {
      execFile(exe, args(seek), { timeout: 30000, windowsHide: true }, (err) => {
        if (err || !fs.existsSync(tmp) || fs.statSync(tmp).size === 0) {
          try { fs.rmSync(tmp, { force: true }); } catch {}
          if (onFail) return onFail();
          return resolve(false);
        }
        try {
          fs.renameSync(tmp, dest);
          resolve(true);
        } catch { resolve(false); }
      });
    };
    run('00:00:01', () => run(null, null));       // 先试第 1 秒,失败再试第一帧
  });
}

/** 取低清预览图;没有就现场生成一次,仍失败则返回 null(由调用方回退到原图)。 */
async function serveThumb(ctx, req, res, url) {
  try {
    const rel = url.searchParams.get('path') || '';
    const { abs } = await resolveExisting(ctx, rel);
    const st = await fsp.stat(abs).catch(() => null);
    if (!st || st.isDirectory()) throw new HttpError(404, '文件不存在');
    if (!isImageName(abs) && !isVideoName(abs)) throw new HttpError(415, '该文件不是可生成封面的图片或视频');

    let dest = thumbPathOf(abs);
    let dstat = await fsp.stat(dest).catch(() => null);
    if (!dstat || dstat.mtimeMs < st.mtimeMs) {
      const ok = await generateThumb(abs);
      if (!ok) throw new HttpError(503, '未能生成低清预览(服务端未安装 sharp 或该图片无法解码)');
      dstat = await fsp.stat(dest).catch(() => null);
      if (!dstat) throw new HttpError(503, '未能生成低清预览');
    }
    // 缩略图同理:加 ETag/Last-Modified 与 304 协商,避免每次进目录都把整套缩略图重拉一遍
    const { etag, lastModified } = validatorsOf(dstat);
    const head = {
      'Content-Type': 'image/jpeg',
      'Content-Length': dstat.size,
      'Cache-Control': 'private, max-age=86400, must-revalidate',
      'ETag': etag,
      'Last-Modified': lastModified,
      'X-Content-Type-Options': 'nosniff',
      // 缩略图与 /raw 一致:即使将来 MIME 判断出偏差,内容也被沙箱化,不会执行脚本
      'Content-Security-Policy': "sandbox; default-src 'none'; style-src 'unsafe-inline'",
    };
    if (isFresh(req, dstat)) {
      res.writeHead(304, { 'ETag': etag, 'Last-Modified': lastModified, 'Cache-Control': head['Cache-Control'] });
      return res.end();
    }
    if (req.method === 'HEAD') { res.writeHead(200, head); return res.end(); }
    res.writeHead(200, head);
    const f = fs.createReadStream(dest);
    pipeline(f, res).catch(() => { f.destroy(); });
  } catch (e) {
    if (e instanceof HttpError) return sendJson(res, e.status, { ok: false, error: e.message });
    // resolveExisting 对不存在的路径抛 ENOENT,这里统一映射为 404(与其它接口一致)
    if (e && e.code === 'ENOENT') return sendJson(res, 404, { ok: false, error: '文件不存在' });
    if (e && (e.code === 'EACCES' || e.code === 'EPERM')) return sendJson(res, 403, { ok: false, error: '没有访问权限' });
    return sendJson(res, 500, { ok: false, error: `读取预览图失败: ${e.message}` });
  }
}

/* ---------------- 本机文件夹选择框(Windows 原生) ---------------- */

/**
 * 弹出 Windows 原生的「选择文件夹」对话框,把用户选中的绝对路径回传给网页。
 *
 * 之所以放在服务端:浏览器出于安全限制拿不到本地文件的真实绝对路径
 * (webkitdirectory 只给相对路径,showDirectoryPicker 只给句柄),只有本机进程才能拿到。
 *
 * 安全与限制:
 *   - 只有本机请求才能调用(与分享管理同样的判定),外部设备调不到;
 *   - 需要桌面会话;若服务跑在无桌面的环境(服务/远程会话),PowerShell 会失败,
 *     此时返回明确错误,让前端降级为手动填写路径;
 *   - 对话框会阻塞,所以加超时;同一时刻只允许一个弹窗,避免堆叠。
 */

let pickInFlight = false;

function handlePickFolder(ctx, req, res) {
  if (!IS_WIN) {
    return sendJson(res, 501, { ok: false, error: '仅 Windows 支持调用系统文件夹选择框,请手动填写路径' });
  }
  if (pickInFlight) {
    return sendJson(res, 409, { ok: false, error: '已经有一个选择框打开了,请先完成它' });
  }
  pickInFlight = true;
  const t0 = Date.now();

  // 用 PowerShell 调 WinForms 的 FolderBrowserDialog。
  // 输出只用一行路径,便于解析;取消时输出空行。
  const ps = [
    'Add-Type -AssemblyName System.Windows.Forms | Out-Null',
    '$d = New-Object System.Windows.Forms.FolderBrowserDialog',
    "$d.Description = '选择要共享的文件夹'",
    '$d.ShowNewFolderButton = $true',
    'try { $r = $d.ShowDialog() } catch { [Console]::Out.Write("ERR:" + $_.Exception.Message); exit 1 }',
    'if ($r -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write($d.SelectedPath) }',
    'else { [Console]::Out.Write("") }',
  ].join('; ');

  const { execFile } = require('node:child_process');
  execFile('powershell', ['-NoProfile', '-STA', '-Command', ps],
    { timeout: 5 * 60 * 1000, windowsHide: true, maxBuffer: 64 * 1024 },
    (err, stdout, stderr) => {
      pickInFlight = false;
      const ms = Date.now() - t0;
      if (err) {
        const msg = String(stderr || err.message || '').trim().slice(0, 200);
        logAction({ action: 'deny', ctx, req, ok: false, status: 500,
                    detail: `打开文件夹选择框失败: ${msg || '无桌面会话或 PowerShell 不可用'}` });
        return sendJson(res, 500, {
          ok: false,
          error: '无法弹出系统选择框(可能是无桌面会话或 PowerShell 受限),请改为手动填写路径',
        });
      }
      const out = String(stdout || '').trim();
      if (out.startsWith('ERR:')) {
        logAction({ action: 'deny', ctx, req, ok: false, status: 500, detail: `选择框出错: ${out.slice(4, 120)}` });
        return sendJson(res, 500, { ok: false, error: '系统选择框出错,请改为手动填写路径' });
      }
      if (!out) {
        logAction({ action: 'sharePick', ctx, req, ok: true, detail: `用户取消了选择(${ms}ms)` });
        return sendJson(res, 200, { ok: true, cancelled: true });
      }
      logAction({ action: 'sharePick', ctx, req, path: out, ok: true, detail: `选择了本机文件夹(${ms}ms)` });
      return sendJson(res, 200, { ok: true, path: out });
    });
}

/* ---------------- 单独分享文件夹 ---------------- */

/**
 * 把共享根内的某个子文件夹，用「独立端口 + 独立作用域」对外分享:
 *   - 功能与主共享一致(浏览/下载/上传/删除/重命名/预览/实时同步);
 *   - 独立端口 + 独立 HTTPS 监听,与主端口互不影响,可单独取消;
 *   - 可设访问口令(HTTP Basic),不设则靠端口隔离;
 *   - 不允许在已分享的文件夹内部再分享一层(父子关系一律拒绝);
 *   - 仅本机网页端能创建/取消。
 * 记录持久化到 shares.json,进程重启后自动恢复。
 */

const shares = new Map();     // id -> share 记录
const shareServers = new Map(); // id -> https.Server
let shareSeq = 0;

function shareInfo(sh) {
  return {
    id: sh.id,
    name: sh.name,
    rel: sh.rel,
    absRoot: sh.absRoot || sh.real || '',   // 该分享对应的真实目录(外部分享时是绝对路径)
    external: !!sh.external,                // 是否来自共享根之外(界面会加标注)
    port: sh.port,
    needPwd: !!sh.pwdHash || !!sh.roHash,
    hasRw: !!sh.pwdHash,        // 是否设了读写口令
    hasRo: !!sh.roHash,         // 是否设了只读口令
    readonly: !sh.pwdHash && !!sh.roHash,  // 只有只读口令:整个分享都是只读的
    webdav: !!sh.webdav,        // 是否启用 WebDAV(可被 Windows 映射为网络位置)
    pwdHint: sh.pwdHint || '',
    createdAt: sh.createdAt,
    urls: shareUrls(sh.port),
  };
}

/** 某个端口对外可用的访问地址(本机 + 各局域网 IPv4/IPv6 地址)。 */
function shareUrls(port) {
  const urls = [`https://localhost:${port}/`];
  const addrs = lanAddrs();
  for (const ip of addrs.v4) urls.push(`https://${ip}:${port}/`);
  for (const ip of addrs.v6) urls.push(`https://${ip}:${port}/`);   // IPv6 已带 [ ]
  return urls;
}

function loadShares() {
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    if (Array.isArray(raw.shares)) {
      for (const s of raw.shares) {
        if (!s || typeof s.rel !== 'string' || !Number(s.port)) continue;
        const id = s.id || `s${++shareSeq}`;
        const m = /^s(\d+)$/.exec(id);
        if (m) shareSeq = Math.max(shareSeq, Number(m[1]));
        shares.set(id, {
          id,
          name: s.name || (s.external ? path.basename(s.absRoot || s.rel || '') : path.posix.basename(s.rel)),
          rel: (s.rel || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, ''),
          absRoot: s.absRoot || '',      // 外部分享的绝对路径(共享根内分享为空)
          external: !!s.external,        // 是否来自共享根之外
          port: Number(s.port),
          pwdHash: s.pwdHash || '',
          roHash: s.roHash || '',        // 只读口令(旧记录没有则为空)
          webdav: !!s.webdav,            // 是否启用 WebDAV
          pwdHint: s.pwdHint || '',
          createdAt: s.createdAt || Date.now(),
          real: s.real || s.absRoot || '',
        });
      }
    }
  } catch { /* 首次运行没有该文件 */ }
}

function saveShares() {
  const out = [...shares.values()].map((s) => ({
    id: s.id, name: s.name, rel: s.rel, port: s.port,
    absRoot: s.absRoot || '', external: !!s.external,   // 外部分享需要记住绝对路径
    pwdHash: s.pwdHash || '', roHash: s.roHash || '', webdav: !!s.webdav,
    pwdHint: s.pwdHint || '', createdAt: s.createdAt,
  }));
  try {
    fs.writeFileSync(STATE_PATH, JSON.stringify({ shares: out }, null, 2), 'utf8');
  } catch (e) {
    errorLine(`无法写入 ${STATE_PATH}: ${e.message}`);
  }
}

/**
 * 比较两个共享根内相对路径是否相同。Windows 文件系统大小写不敏感,
 * "Sub" 与 "sub" 是同一目录,必须归一化后再比,否则可绕过「禁止嵌套分享」。
 */
function relEq(a, b) {
  const x = String(a || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const y = String(b || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  return IS_WIN ? x.toLowerCase() === y.toLowerCase() : x === y;
}
/** b 是否在 a 之内(a 的子孙)。a 为空视为“没有根”,一律返回 false。 */
function relInside(a, b) {
  const x = String(a || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const y = String(b || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  // 注意:这里必须对空 a 返回 false。
  // 早先写成 `if (!x) return !!y`,导致“记录里还没有真实路径(real 为空)”的分享
  // 会被当成“任何目录都在它之内”,于是新建分享一律误报 409 包含关系。
  if (!x || !y) return false;
  const [p, q] = IS_WIN ? [x.toLowerCase(), y.toLowerCase()] : [x, y];
  return q.startsWith(p + '/');
}

/** 校验某个 rel 是否是「已分享的文件夹本身或其后代」(用于禁止嵌套分享)。 */
function findSharingAncestor(rel) {
  for (const sh of shares.values()) {
    // 待分享的目录位于某个已分享目录内(含自身)
    if (relEq(rel, sh.rel) || relInside(sh.rel, rel)) return sh;
  }
  // 反向:待分享的目录是某个已分享目录的祖先(把父目录分享出去会连子分享一起暴露)
  for (const sh of shares.values()) {
    if (relInside(rel, sh.rel)) return sh;
  }
  return null;
}

/** 口令哈希:用 scrypt 加盐,避免明文落盘。 */
function hashPwd(pwd, salt) {
  const crypto = require('node:crypto');
  const s = salt || crypto.randomBytes(8).toString('hex');
  const h = crypto.scryptSync(String(pwd), s, 32).toString('hex');
  return `${s}:${h}`;
}

/**
 * 校验口令。注意:stored 为空表示「该分享没有设口令」,此时必须由调用方显式放行,
 * 本函数对空 stored 一律返回 false(fail-closed),避免分享记录被移除后误放行。
 */
function verifyPwd(pwd, stored) {
  if (!stored) return false;
  const [salt, want] = String(stored).split(':');
  const crypto = require('node:crypto');
  const calc = crypto.scryptSync(String(pwd), salt, 32).toString('hex');
  const a = Buffer.from(calc);
  const b = Buffer.from(want || '');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * 判定请求携带的口令对应的权限级别。
 * 返回 { level: 'rw' | 'ro' | 'none', matched }:
 *   rw   —— 命中读写口令(或该分享未设任何口令时的默认放行,由调用方判断)
 *   ro   —— 命中只读口令:可浏览/下载/预览,但所有写操作一律拒绝
 *   none —— 未提供或不匹配
 * 两个口令都做常量时间比较,且先比读写再比只读,避免因短路造成明显的时序差异。
 */
function verifyPwdRole(sh, pwd) {
  if (pwd === null || pwd === undefined) return { level: 'none', matched: false };
  const hitRw = sh.pwdHash ? verifyPwd(pwd, sh.pwdHash) : false;
  const hitRo = sh.roHash ? verifyPwd(pwd, sh.roHash) : false;
  if (hitRw) return { level: 'rw', matched: true };
  if (hitRo) return { level: 'ro', matched: true };
  return { level: 'none', matched: false };
}

/**
 * 口令校验失败按来源 IP 退避,并对并发校验数设上限:
 * scrypt 是同步 CPU 密集操作,若不限流,未认证请求可反复触发它来独占事件循环,
 * 把该分享端口乃至同进程的主端口一起拖慢。这里做最小必要的防护。
 */
const PWD_FAIL_LIMIT = 6;      // 窗口内允许的失败次数
const PWD_FAIL_WINDOW = 60_000; // 窗口长度
const PWD_MAX_CONCURRENT = 4;  // 同时进行的 scrypt 校验上限
const pwdFails = new Map();    // ip -> { n, until }
let pwdInFlight = 0;

function pwdBlocked(ip) {
  const rec = pwdFails.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.until) { pwdFails.delete(ip); return false; }
  return rec.n >= PWD_FAIL_LIMIT;
}
function notePwdFail(ip) {
  const now = Date.now();
  const rec = pwdFails.get(ip);
  if (!rec || now > rec.until) pwdFails.set(ip, { n: 1, until: now + PWD_FAIL_WINDOW });
  else rec.n++;
  if (pwdFails.size > 500) { // 防止无限增长
    for (const [k, v] of pwdFails) if (now > v.until) pwdFails.delete(k);
  }
}
function notePwdOk(ip) { pwdFails.delete(ip); }

/**
 * 判断一个请求是否属于“写操作”(会被只读口令拒绝)。
 * 采用白名单思路:只有明确列举的读操作才放行,其余一律视为写操作,
 * 这样将来新增接口时默认是安全的(忘记登记最多是“只读用户用不了”,而不是“越权写”)。
 */
const READONLY_ALLOWED = new Set([
  '/',                        // 页面本身
  '/api/list',                // 列目录
  '/api/events',              // 实时同步(只读)
  '/download',                // 下载
  '/api/download-zip/get',    // 批量下载的取包(支持 Range 续传)
  '/api/download-zip/status', // 批量下载的进度查询
  '/raw',                     // 预览原图
  '/thumb',                   // 低清预览图
]);
// 这些接口虽是 POST(要带选中列表,放在 body 更省长度),但并不写共享目录,
// 因此对只读用户也放行 —— 批量下载本就是读操作。
const READONLY_ALLOWED_POST = new Set([
  '/api/download-zip/prepare',
]);
function isWriteRequest(method, pathname) {
  if (method === 'GET' || method === 'HEAD') {
    // 允许列表内的 GET/HEAD 请求;其它 GET 接口(如 /api/upload/status)也不写盘,
    // 但为简洁起见这里只放行必要的几个,status 查询单独放行。
    return !(READONLY_ALLOWED.has(pathname) || pathname === '/api/upload/status');
  }
  if (READONLY_ALLOWED_POST.has(pathname)) return false;
  // 其余非 GET/HEAD 一律是写操作(上传分片、收尾、删除、重命名、建目录、分享管理等)
  return true;
}

/** 从请求里取 Basic 口令。 */
function basicPwd(req) {
  const h = req.headers.authorization || '';
  const m = /^Basic\s+(.+)$/i.exec(h);
  if (!m) return null;
  try {
    const raw = Buffer.from(m[1], 'base64').toString('utf8');
    const i = raw.indexOf(':');
    return i >= 0 ? raw.slice(i + 1) : null;
  } catch { return null; }
}

/* ---------------- 访问口令挑战 & 主端口「根目录访问密码」 ---------------- */

/**
 * 统一的「口令挑战」:没带口令或口令不对 → 401(浏览器会弹出输入框);
 * 同一 IP 连续试错过多 → 429 退避。这两种情况都已自行写出响应并返回 null,
 * 调用方拿到 null 直接 return 即可。
 * 通过校验则返回 { level:'rw'|'ro' },调用方据此决定权限。
 * verify(pwd) 由调用方给出:单独分享有读写/只读两个口令,主端口只有一个访问密码。
 */
function challengeAccess(req, res, ctx, verify, errDetail) {
  const ip = clientIP(req);
  if (pwdBlocked(ip)) {
    res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '60', 'Cache-Control': 'no-store' });
    logAction({ action: 'deny', ctx, req, ok: false, status: 429, detail: '口令尝试过于频繁' });
    res.end('口令尝试过于频繁,请稍后再试');
    return null;
  }
  const pwd = basicPwd(req);
  // scrypt 是同步 CPU 密集操作:限制同时在跑的校验数,避免未认证请求反复触发它拖垮整个进程
  let role = { level: 'none', matched: false };
  if (pwd !== null && pwdInFlight < PWD_MAX_CONCURRENT) {
    pwdInFlight++;
    try { role = verify(pwd); } finally { pwdInFlight--; }
  }
  if (!role.matched) {
    if (pwd !== null) notePwdFail(ip);
    res.writeHead(401, {
      'WWW-Authenticate': 'Basic realm="lan-file-share", charset="UTF-8"',
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    logAction({ action: 'deny', ctx, req, ok: false, status: 401, detail: errDetail || '口令错误或未提供' });
    res.end('需要访问口令');
    return null;
  }
  notePwdOk(ip);
  return role;
}

/* ---- 主端口「根目录访问密码」---- */

/**
 * 局域网访问主共享所需的密码,只能在本机网页端设置(见 handleShareApi 里的 /api/rootpwd)。
 * 哈希与单独分享口令共用同一套 scrypt 方案,持久化在 rootauth.json;空串表示未启用。
 * 本机(回环与本机网卡 IP)按设计免输,判定见 isLocalRequest —— 与「分享管理仅限本机」一致。
 */
let rootPwdHash = '';

function loadRootAuth() {
  try {
    const raw = JSON.parse(fs.readFileSync(ROOT_AUTH_PATH, 'utf8'));
    rootPwdHash = typeof raw.pwdHash === 'string' ? raw.pwdHash : '';
  } catch { rootPwdHash = ''; }   // 从没设置过(或文件被手工删掉)视为未启用
}

/** 落盘。取消密码时删除文件,不留空壳;写入失败抛 HttpError,由调用方回滚内存状态。 */
function saveRootAuth() {
  try {
    if (!rootPwdHash) { try { fs.rmSync(ROOT_AUTH_PATH, { force: true }); } catch {} return; }
    fs.writeFileSync(ROOT_AUTH_PATH, JSON.stringify({ pwdHash: rootPwdHash }, null, 2), 'utf8');
  } catch (e) {
    throw new HttpError(500, `无法保存访问密码(${ROOT_AUTH_PATH}):${e.message}`);
  }
}

/** 设置 / 取消根目录访问密码(传空串表示取消)。落盘成功才生效,并立即踢掉已连着的局域网会话。 */
function setRootPwd(password) {
  const prev = rootPwdHash;
  rootPwdHash = password ? hashPwd(password) : '';
  try {
    saveRootAuth();
  } catch (e) {
    rootPwdHash = prev;   // 回滚:不能出现“界面上显示已设置、重启后却没了”
    throw e;
  }
  dropSessions('main');   // 断开主端口已建立的 SSE,客户端下一次请求就会要求(重新)输入密码
}

/** 校验主端口访问密码:只有一个密码,命中即读写权限。 */
function verifyRootPwd(pwd) {
  const hit = !!rootPwdHash && verifyPwd(pwd, rootPwdHash);
  return { level: hit ? 'rw' : 'none', matched: hit };
}

/** 找一个当前空闲的端口(从 sharePortBase 起试)。 */
async function findFreePort(start) {
  const net = require('node:net');
  const used = new Set([PORT, ...[...shares.values()].map((s) => s.port)]);
  for (let p = start; p < start + 500; p++) {
    if (used.has(p)) continue;
    const free = await new Promise((resolve) => {
      const srv = net.createServer();
      srv.once('error', () => resolve(false));
      srv.once('listening', () => srv.close(() => resolve(true)));
      srv.listen(p, '0.0.0.0');
    });
    if (free) return p;
  }
  throw new HttpError(500, '找不到可用端口,请在 config.json 调整 sharePortBase');
}

/**
 * 创建单独分享。rel 为共享根内的相对目录路径(必须真实存在于共享根内)。
 * opts = { rel, port?, password? }
 */
/**
 * 外部文件夹分享的安全闸门:拒绝把「整盘根」或「盘符下的系统目录」直接开成公开共享。
 *
 * 判定范围刻意收窄:只看盘符/根之下**第一层**目录名。
 * 原因:按任意层级匹配会把 C:/Users/example/Documents/照片 这类正常位置也误伤
 * (路径里出现了 users),而真正要防的是"手滑选中 C:/Windows 或 C:/Users 本身"。
 */
const EXTERNAL_DENY_FIRST = new Set([
  'windows', 'program files', 'program files (x86)', 'programdata', 'users',
  'documents and settings', 'system volume information', 'recovery', 'perflogs',
  '$recycle.bin', 'msocache', 'intel', 'nvidia',
  'etc', 'bin', 'sbin', 'boot', 'dev', 'proc', 'sys', 'usr', 'var', 'root', 'lib',
]);
function assertSafeExternalRoot(abs) {
  const norm = path.resolve(abs);
  const parsed = path.parse(norm);
  // 1) 整盘根(如 C:\ 或 /):解析出来的 root 等于自身
  if (path.resolve(parsed.root) === norm) {
    throw new HttpError(400, '不能直接分享整个磁盘根目录。请改选一个具体的子文件夹。');
  }
  // 2) 只看根之下的第一层目录名(大小写不敏感)
  const rest = norm.slice(parsed.root.length);
  const first = rest.split(/[\\/]+/).filter(Boolean)[0];
  if (first && EXTERNAL_DENY_FIRST.has(first.toLowerCase())) {
    throw new HttpError(400, '该目录是系统关键位置(如 Windows / Program Files / Users 本身),不允许直接分享。'
      + '若确需共享其中的内容,请进入它的子目录再分享。');
  }
  return true;
}

async function createShare(opts) {
  const rawRel = String(opts.rel || '').trim();
  const absInput = String(opts.absPath || '').trim();   // 外部文件夹:直接给绝对路径

  if (shares.size >= 32) throw new HttpError(400, '同时分享的文件夹过多(上限 32),请先取消一些');

  const ctxMain = makeCtxMain();
  let abs;          // 该分享的真实根目录
  let rel;          // 共享根内的相对路径(仅共享根内分享有意义)
  let external;     // 是否来自共享根之外

  if (absInput) {
    // ---- 情况 A:分享共享根之外的本机文件夹(管理员在网页端指定) ----
    if (IS_WIN) {
      // 必须是绝对路径(带盘符),避免相对路径依赖进程 CWD 而含义不明
      if (!/^[a-zA-Z]:[\\/]/.test(absInput) && !/^\\\\/.test(absInput)) {
        throw new HttpError(400, '请填写完整的绝对路径,例如 D:/照片 或 \\\\服务器\\共享');
      }
    } else if (!absInput.startsWith('/')) {
      throw new HttpError(400, '请填写完整的绝对路径,例如 /home/user/photos');
    }
    // realpath 解析:确认存在、并且落定真实路径(后续所有访问都以它为准,防符号链接逃逸)
    try {
      abs = await fsp.realpath(path.resolve(absInput));
    } catch (e) {
      throw new HttpError(404, `该路径不存在或无法访问: ${e.message}`);
    }
    const st0 = await fsp.stat(abs);
    if (!st0.isDirectory()) throw new HttpError(400, '只能分享文件夹,不能分享单个文件');
    // 拒绝把整盘根/系统关键目录作为分享根:这类误操作后果严重,直接挡掉
    assertSafeExternalRoot(abs);
    external = true;
    rel = '';        // 外部分享没有"共享根内相对路径"的概念
  } else {
    // ---- 情况 B:分享共享根内的子文件夹(原有行为) ----
    rel = rawRel.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    if (!rel) throw new HttpError(400, '不能在共享根上创建单独分享(请选择子文件夹)');
    assertRelSegmentsAll(rel);
    const got = await resolveExisting(ctxMain, rel).catch((e) => {
      throw new HttpError(e && e.status === 403 ? 403 : 404, '要分享的文件夹不存在(或不在共享目录内)');
    });
    abs = got.abs;
    const st = await fsp.stat(abs);
    if (!st.isDirectory()) throw new HttpError(400, '只能分享文件夹,不能分享单个文件');
    const dup = findSharingAncestor(rel);
    if (dup) throw new HttpError(409, `该文件夹与已分享的「${dup.name}」存在包含关系,不能重复分享`);
    external = false;
  }

  // 外部分享:也要检查与已有分享是否存在包含关系(否则同一个目录可能被开两次,
  // 或者把已分享目录的父目录再分享一次,等于绕过了"禁止嵌套"的初衷)。
  if (external) {
    for (const s of shares.values()) {
      if (!s.real) continue;
      if (relEq(abs, s.real) || relInside(s.real, abs) || relInside(abs, s.real)) {
        throw new HttpError(409, `该文件夹与已分享的「${s.name}」存在包含关系,不能重复分享`);
      }
    }
    // 关键:外部分享不能把「共享根」牵扯进来,否则等于通过另一条路径
    // 重新暴露主共享的内容,绕过了主共享本想设定的边界。
    // 三种情况都拒绝:(a) 就是共享根,(b) 在共享根之内,(c) 是共享根的上级。
    const rootReal = SHARE_ROOT_REAL;
    if (relEq(abs, rootReal)) {
      throw new HttpError(409, '这就是「共享根」本身,请用主共享来提供,不能作为外部目录再次分享。');
    }
    if (relInside(abs, rootReal)) {
      throw new HttpError(409, '该目录位于「共享根」之内,请用主页面里的「分享」按钮来分享它。');
    }
    if (relInside(rootReal, abs)) {
      throw new HttpError(409, '该目录是「共享根」的上级,分享它会连带暴露共享根及其全部内容,已拒绝。请改选一个不含共享根的目录。');
    }
  } else {
    // 共享根内的分享:也要确认它没有落在某个"外部分享"的目录里面
    for (const s of shares.values()) {
      if (!s.external || !s.real) continue;
      if (relInside(s.real, abs)) {
        throw new HttpError(409, `该文件夹位于已分享的「${s.name}」之内,不能重复分享`);
      }
    }
  }

  let port = Number(opts.port) || 0;
  if (port) {
    if (port === PORT) throw new HttpError(400, `端口 ${port} 已被主共享占用`);
    if ([...shares.values()].some((s) => s.port === port)) throw new HttpError(409, `端口 ${port} 已被另一个分享占用`);
    if (port < 1024 || port > 65535) throw new HttpError(400, '端口需在 1024-65535 之间');
    const ok = await new Promise((resolve) => {
      const srv = require('node:net').createServer();
      srv.once('error', () => resolve(false));
      srv.once('listening', () => srv.close(() => resolve(true)));
      srv.listen(port, '0.0.0.0');
    });
    if (!ok) throw new HttpError(409, `端口 ${port} 已被其它程序占用,请换一个或留空自动分配`);
  } else {
    port = await findFreePort(SHARE_PORT_BASE);
  }

  const id = `s${++shareSeq}`;
  const sh = {
    id,
    // 外部分享没有"共享根内相对路径",用绝对路径作为显示名;名称取末级目录名
    name: external ? (path.basename(abs) || abs) : path.posix.basename(rel),
    rel,
    absRoot: abs,                                            // 该分享的真实根目录(绝对)
    external,                                                // 是否来自共享根之外
    real: abs,
    port,
    pwdHash: opts.password ? hashPwd(opts.password) : '',   // 读写口令
    roHash: opts.roPassword ? hashPwd(opts.roPassword) : '', // 只读口令
    webdav: !!opts.webdav,                                   // 是否启用 WebDAV
    pwdHint: '',
    createdAt: Date.now(),
  };
  await listenShare(sh);
  shares.set(id, sh);
  saveShares();
  return sh;
}

function assertRelSegmentsAll(rel) {
  for (const seg of rel.split('/')) assertRelSegment(seg);
}

/** 为一个分享启动独立 HTTPS 监听(IPv4 + IPv6 双栈,IPv6 不可用时自动退回 IPv4)。 */
function listenShare(sh) {
  return new Promise((resolve, reject) => {
    const server = https.createServer(
      { cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) },
      (req, res) => handleRequest(makeCtxShare(sh), req, res)
    );
    let settled = false;
    listenDual(server, sh.port, () => {
      settled = true;
      shareServers.set(sh.id, server);
      note('单独分享  ', paint(`「${sh.name}」`, C.bold + C.magenta)
        + ' ' + paint(`https://localhost:${sh.port}/`, C.bold + C.brightGreen)
        + paint(`  (${sh.rel})`, C.dim));
      resolve(server);
    }, (e) => {
      if (!settled) { settled = true; reject(e); }
      else errorLine(`分享「${sh.name}」(端口 ${sh.port}) 出错: ${e.message}`);
    });
  });
}

/** 取消一个分享(停止端口监听并移除记录)。 */
async function removeShare(id) {
  const sh = shares.get(id);
  if (!sh) throw new HttpError(404, '该分享不存在或已取消');
  const retry = shareRetryTimers.get(id);
  if (retry) { clearInterval(retry); shareRetryTimers.delete(id); }
  const server = shareServers.get(id);
  shareServers.delete(id);
  shares.delete(id);          // 先移除记录:已建立的 keep-alive 连接随后会被下面的校验拒绝
  saveShares();
  if (server) {
    // 断开该端口上的长连接(SSE),再关闭监听;waitForClients 不必,直接 close 即可
    for (const c of [...sseClients]) if (c.scope === id) { try { c.res.end(); } catch {} sseClients.delete(c); }
    server.closeAllConnections?.();   // Node 18.2+:立即断开仍在 keep-alive 的空闲连接
    await new Promise((r) => server.close(() => r()));
  }
  return sh;
}

/** 修改某个分享的口令(传空字符串表示取消口令)。 */
function setSharePwd(sh, password) {
  sh.pwdHash = password ? hashPwd(password) : '';
  saveShares();
  // 口令变化后,该端口上已建立的 SSE 长连接应断开,迫使客户端重新认证
  dropSessions(sh.id);
}

/** 修改某个分享的只读口令(传空字符串表示取消只读口令)。 */
function setShareRoPwd(sh, roPassword) {
  sh.roHash = roPassword ? hashPwd(roPassword) : '';
  saveShares();
  dropSessions(sh.id);
}

/** 断开某个作用域上已建立的 SSE 长连接(口令或权限变化后强制重新认证)。scope 为 'main' 或 shareId。 */
function dropSessions(scope) {
  for (const c of [...sseClients]) if (c.scope === scope) { try { c.res.end(); } catch {} sseClients.delete(c); }
}

/**
 * 修改某个分享的端口:先停掉旧监听,再用新端口重新监听。
 * 失败(新端口被占用)时回滚到原端口,保证分享不会因为一次改端口而不可用。
 */
async function setSharePort(sh, newPort) {
  const port = Number(newPort) || 0;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new HttpError(400, '端口需在 1024-65535 之间');
  }
  if (port === sh.port && shareServers.has(sh.id)) return sh;
  if (port === PORT) throw new HttpError(400, `端口 ${port} 已被主共享占用`);
  if ([...shares.values()].some((s) => s.id !== sh.id && s.port === port)) {
    throw new HttpError(409, `端口 ${port} 已被另一个分享占用`);
  }

  const oldPort = sh.port;
  const oldServer = shareServers.get(sh.id);
  const retry = shareRetryTimers.get(sh.id);
  if (retry) { clearInterval(retry); shareRetryTimers.delete(sh.id); }
  if (oldServer) {
    shareServers.delete(sh.id);
    dropSessions(sh.id);
    oldServer.closeAllConnections?.();
    await new Promise((r) => oldServer.close(() => r()));
  }

  sh.port = port;
  try {
    await listenShare(sh);
    saveShares();
    publishChange('up', '');
    return sh;
  } catch (e) {
    sh.port = oldPort;                       // 回滚,避免把分享改坏
    try { await listenShare(sh); } catch { scheduleShareRetry(sh); }
    saveShares();
    throw new HttpError(409, `改用端口 ${port} 失败(${e.code === 'EADDRINUSE' ? '端口被占用' : e.message}),已回滚到 ${oldPort}`);
  }
}

/* ---------------- WebDAV(把分享映射成 Windows 网络位置) ---------------- */

/**
 * 在「单独分享」的端口之外,再为同一个文件夹提供 WebDAV 服务,
 * 这样 Windows 用户可以「映射网络驱动器」把分享挂成一个盘符/网络位置。
 *
 * 设计要点:
 *   - WebDAV 监听在分享端口 + 1000 的偏移端口上(例如分享 9000 → WebDAV 9001),
 *     不用额外配置,也不会与其它分享冲突(占用时会自动换一个空闲端口);
 *   - 复用同一张 HTTPS 证书(Windows 需要先信任该证书,否则会拒绝连接);
 *   - 鉴权复用分享自身的口令:读写口令获得读写权限,只读口令只有读权限;
 *   - 与网页端共用同一个根目录,任何一方改动另一方都能通过实时同步看到。
 */

let webdavLib = null;
let webdavLoadTried = false;
function loadWebdav() {
  if (webdavLoadTried) return webdavLib;
  webdavLoadTried = true;
  try {
    webdavLib = require('webdav-server');
  } catch {
    webdavLib = null;
  }
  return webdavLib;
}

const webdavServers = new Map();   // shareId -> WebDAVServer

/** WebDAV 端口:优先用分享端口 +1000,被占用则自动找一个空闲端口。 */
async function findWebdavPort(sh) {
  const net = require('node:net');
  const used = new Set([
    PORT, ...[...shares.values()].map((s) => s.port),
    ...[...webdavServers.values()].map((s) => s.options && s.options.port),
  ]);
  const tryPort = (p) => new Promise((resolve) => {
    if (p < 1024 || p > 65535 || used.has(p)) return resolve(false);
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(p, '0.0.0.0');
  });
  const preferred = sh.port + 1000;
  if (await tryPort(preferred)) return preferred;
  for (let p = SHARE_PORT_BASE + 1000; p < SHARE_PORT_BASE + 1400; p++) {
    if (await tryPort(p)) return p;
  }
  throw new HttpError(500, '找不到可用的 WebDAV 端口');
}

/** 为一个分享启用 WebDAV。 */
async function startWebdav(sh) {
  const lib = loadWebdav();
  if (!lib) throw new HttpError(503, '服务端未安装 webdav-server,请运行 npm install webdav-server');

  const port = await findWebdavPort(sh);

  // 权限:读写口令 → 全权限;只读口令 → 仅读取与列目录
  const privileges = new lib.v2.PrivilegeManager();
  const ALL = ['canRead', 'canReadLocks', 'canReadContent', 'canReadProperties',
               'canWrite', 'canWriteLocks', 'canWriteContent', 'canWriteProperties',
               'canCreate', 'canDelete', 'canMove', 'canRename', 'canSource'];
  const READ_ONLY = ['canRead', 'canReadLocks', 'canReadContent', 'canReadProperties', 'canSource'];

  /**
   * 自定义用户管理器:把口令校验接到本服务自己的 scrypt 哈希上。
   * webdav-server 默认按明文比对,这里改为动态校验,避免把明文口令留在内存。
   * 用户名只是占位(客户端填什么都行),真正的判据是“口令命中哪一个”。
   */
  class ShareUserManager extends lib.v2.SimpleUserManager {
    getUserByNamePassword(name, password, callback) {
      const role = verifyPwdRole(sh, password);
      if (!role.matched) return callback(new Error('bad credentials'));
      const uname = role.level === 'rw' ? 'rw' : 'ro';
      const u = this.users[uname] || this.addUser(uname, null, false);
      return callback(null, u);
    }
    // 未设任何口令时,允许匿名(与网页端一致)
    getDefaultUser(callback) {
      if (!sh.pwdHash && !sh.roHash) {
        const u = this.users.guest || this.addUser('guest', null, false);
        return callback(u);
      }
      callback(this.users.__default);   // 有口令时必须认证
    }
  }

  const users = new ShareUserManager();
  users.addUser('rw', null, false);
  users.addUser('ro', null, false);
  users.addUser('guest', null, false);
  privileges.setUserPrivileges(users.users.rw, ALL);
  privileges.setUserPrivileges(users.users.ro, READ_ONLY);
  privileges.setUserPrivileges(users.users.guest, sh.pwdHash || sh.roHash ? [] : ALL);

  const auth = new lib.v2.HTTPBasicAuthentication(users, 'lan-file-share');

  const server = new lib.WebDAVServer({
    port,
    // 与网页端保持一致:能用 IPv6 就用 '::'(双栈),否则退回 IPv4
    hostname: ipv6Available() ? '::' : '0.0.0.0',
    https: { cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) },
    httpAuthentication: auth,
    privilegeManager: privileges,
    maxRequestDepth: -1,
    strictMode: false,
    // 有口令时必须认证
    requireAuthentification: !!(sh.pwdHash || sh.roHash),
  });

  // 每个分享一个独立的 server 实例,物理目录直接挂到虚拟根 "/",
  // 这样 Windows 访问 https://host:port/ 就是分享目录本身。
  const physFs = new lib.v2.PhysicalFileSystem(sh.real);
  server.setFileSystem('/', physFs, () => {});

  await new Promise((resolve, reject) => {
    let done = false;
    server.start((httpServer) => {
      httpServer.on('error', (e) => { if (!httpServer.listening && !done) { done = true; reject(e); } });
      if (httpServer.listening) { if (!done) { done = true; resolve(); } }
      else httpServer.once('listening', () => { if (!done) { done = true; resolve(); } });
    });
  });

  sh.webdav = true;
  sh.webdavPort = port;
  webdavServers.set(sh.id, server);
  return { port };
}

/** 关闭某个分享的 WebDAV。 */
async function stopWebdav(sh) {
  const server = webdavServers.get(sh.id);
  webdavServers.delete(sh.id);
  sh.webdav = false;
  sh.webdavPort = 0;
  if (server) {
    await new Promise((resolve) => {
      try {
        const http = server.httpServer;
        if (http) {
          http.closeAllConnections?.();
          http.close(() => resolve());
        } else resolve();
      } catch { resolve(); }
    }).catch(() => {});
  }
}

/** 启用/关闭 WebDAV 的统一入口(供 API 调用)。 */
async function setShareWebdav(sh, enabled) {
  if (enabled) {
    if (webdavServers.has(sh.id)) return;
    if (!sh.real) {
      const ctxMain = makeCtxMain();
      const { abs } = await resolveExisting(ctxMain, sh.rel);
      sh.real = abs;
    }
    try {
      await startWebdav(sh);
    } catch (e) {
      sh.webdav = false;
      throw (e instanceof HttpError) ? e : new HttpError(500, `启用 WebDAV 失败: ${e.message}`);
    }
  } else {
    if (!webdavServers.has(sh.id)) { sh.webdav = false; saveShares(); return; }
    await stopWebdav(sh);
  }
  saveShares();
}

/* ---------------- 页面 ---------------- */

const escHtml = (s) => String(s).replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * 生成页面。ctx 决定标题、是否显示「分享」按钮、以及给前端的视图参数。
 * 主端口页面额外注入分享管理面板与最近日志;单独分享端口则没有这些(功能与原主目录一致)。
 */
function renderPage(ctx) {
  const title = escHtml(ctx.title);
  const canShare = ctx.allowNestedShare ? 'true' : 'false';
  const isMain = ctx.kind === 'main' ? 'true' : 'false';
  // 只读口令进来时,前端隐藏所有写操作入口(服务端也会再拦一次)
  const readonly = (ctx.kind === 'share' && ctx.role === 'ro') ? 'true' : 'false';
  const page = PAGE_HTML
    .replace(/__TITLE__/g, title)
    .replace(/__CAN_SHARE__/g, canShare)
    .replace(/__IS_MAIN__/g, isMain)
    .replace(/__READONLY__/g, readonly);
  return page;
}

const PAGE_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ctext y='26' font-size='26'%3E%F0%9F%93%81%3C/text%3E%3C/svg%3E">
<style>
  :root { color-scheme: light dark; --bd:#e2e5ea; --mut:#6b7280; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, "Segoe UI", "Microsoft YaHei", sans-serif; background:var(--bg,#f6f7f9); color:var(--fg,#1f2328); }
  header { position:sticky; top:0; background:var(--bg,#f6f7f9); border-bottom:1px solid var(--bd); padding:12px 20px; display:flex; align-items:center; gap:12px; flex-wrap:wrap; z-index:5; }
  header h1 { font-size:16px; margin:0; flex:1 1 auto; min-width:160px; }
  main { max-width:900px; margin:0 auto; padding:16px 20px 60px; }
  #crumb { display:flex; align-items:center; gap:4px; font-size:15px; flex-wrap:wrap; margin-bottom:12px; }
  #crumb a, #crumb span.sep { color:var(--accent,#2563eb); text-decoration:none; }
  #crumb a:hover { text-decoration:underline; }
  #drop { position:relative; border:2px dashed var(--bd); border-radius:10px; padding:14px 16px; margin-bottom:14px; display:flex; align-items:center; gap:12px; flex-wrap:wrap; color:var(--mut); background:transparent; transition:background .18s ease, border-color .18s ease; cursor:default; }
  #drop.over { border-color:var(--accent,#2563eb); background:rgba(37,99,235,.06); }
  #drop input { position:absolute; width:1px; height:1px; opacity:0; overflow:hidden; clip:rect(0 0 0 0); pointer-events:none; }
  #drop .btn { flex:0 0 auto; }
  .btn { background:#2563eb; color:#fff; border:0; border-radius:8px; padding:8px 16px; font-size:14px; cursor:pointer; }
  .btn:disabled { opacity:.5; cursor:default; }
  #uploading { margin-bottom:12px; }
  .up-item { display:flex; align-items:center; gap:8px; font-size:13px; padding:6px 10px; color:var(--mut); overflow:hidden; box-sizing:border-box; }
  .up-item.appear { animation:dropIn .24s ease both; }
  .up-item.leave { overflow:hidden; animation:leaveUp .3s ease both; }
  @keyframes dropIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:none; } }
  @keyframes leaveUp { from { height:var(--h,30px); opacity:1; } 30% { opacity:1; } to { height:0; opacity:0; margin-top:0; margin-bottom:0; padding-top:0; padding-bottom:0; transform:translateY(0); } }
  .up-item .bar { flex:1; height:6px; background:var(--bd); border-radius:3px; overflow:hidden; }
  .up-item .bar i { display:block; height:100%; width:0; background:linear-gradient(90deg,#2563eb,#06b6d4); transition:width .18s ease; border-radius:3px; box-shadow:0 0 6px rgba(37,99,235,.35); }
  .btn-lg { display:inline-flex; align-items:center; gap:8px; background:linear-gradient(135deg,#2563eb,#0ea5e9); color:#fff; border:0; border-radius:10px; padding:10px 18px; font-size:15px; cursor:pointer; font-weight:600; box-shadow:0 4px 10px rgba(37,99,235,.28); transition:transform .14s ease, box-shadow .14s ease, filter .14s ease; }
  .btn-lg:hover { transform:translateY(-1px); box-shadow:0 6px 16px rgba(37,99,235,.35); filter:brightness(1.05); }
  .btn-lg.ghost { background:#fff; color:#2563eb; border:1px solid #bcd3ff; box-shadow:0 2px 6px rgba(37,99,235,.12); }
  .btn-lg.ghost:hover { background:#f3f7ff; box-shadow:0 5px 12px rgba(37,99,235,.22); filter:none; }
  .btn-lg:active { transform:translateY(1px); box-shadow:none; }
  .up-ic { font-size:18px; line-height:1; }
  .cta { position:relative; display:flex; align-items:center; gap:14px; flex-wrap:wrap; width:100%; }
  .cta .hint { font-size:13px; color:var(--mut); user-select:none; }
  .up-pop { position:absolute; left:0; top:calc(100% + 6px); min-width:190px; background:var(--card,#fff); border:1px solid var(--bd); border-radius:10px; box-shadow:0 10px 24px rgba(0,0,0,.14); padding:6px; opacity:0; transform:translateY(-6px) scale(.98); transition:opacity .16s ease, transform .16s ease; z-index:20; }
  #drop.open .up-pop { opacity:1; transform:none; }
  .pop-item { display:flex; width:100%; gap:10px; align-items:center; background:none; border:0; padding:9px 12px; border-radius:7px; font-size:14px; color:var(--fg,#1f2328); cursor:pointer; text-align:left; }
  .pop-item:hover { background:rgba(37,99,235,.08); }
  tbody tr { animation:rowIn .18s ease both; }
  @keyframes rowIn { from { opacity:0; transform:translateY(-3px); } to { opacity:1; transform:none; } }
  @media (prefers-reduced-motion: reduce){ .up-pop, tbody tr { transition:none; animation:none; } }
  .up-item.err { color:#dc2626; }
  table { width:100%; border-collapse:collapse; background:var(--card,#fff); border:1px solid var(--bd); border-radius:10px; overflow:hidden; }
  thead th { text-align:left; font-size:12px; color:var(--mut); font-weight:600; padding:8px 12px; border-bottom:1px solid var(--bd); background:var(--th,#fafbfc); }
  td { padding:8px 12px; border-bottom:1px solid var(--bd); font-size:14px; }
  tr:last-child td { border-bottom:0; }
  tr.dir-row { cursor:pointer; }
  tr.dir-row:hover, tr.file-row:hover { background:rgba(37,99,235,.05); }
  .icon { width:26px; text-align:center; }
  .icon img.rowthumb { width:26px; height:26px; object-fit:cover; border-radius:4px; display:block; cursor:zoom-in;
    background:repeating-conic-gradient(#f1f3f6 0% 25%, #e7eaef 0% 50%) 50%/8px 8px; }
  .name { word-break:break-all; }
  .name a { color:inherit; text-decoration:none; }
  .name a:hover { text-decoration:underline; }
  .size, .mtime { color:var(--mut); white-space:nowrap; font-size:13px; }
  .acts { white-space:nowrap; text-align:right; }
  .acts a, .acts button { font-size:13px; color:var(--accent,#2563eb); background:none; border:0; cursor:pointer; text-decoration:none; padding:2px 6px; }
  .acts a:hover, .acts button:hover { text-decoration:underline; }
  .acts .danger, .acts button.danger { color:#dc2626; }
  .btn-sub { background:#2563eb; color:#fff; border:0; border-radius:8px; padding:8px 14px; font-size:14px; cursor:pointer; }
  .btn-ghost { background:none; border:1px solid var(--bd); color:var(--acc,#2563eb); border-radius:8px; padding:8px 14px; cursor:pointer; font-size:14px; }
  .up-choose { display:inline-flex; gap:8px; flex-wrap:wrap; }
  .empty { padding:32px; text-align:center; color:var(--mut); }
  #msg { font-size:13px; margin-top:10px; color:var(--mut); min-height:18px; }
  #msg.err { color:#dc2626; }
  /* ---- 打包下载进度 ---- */
  .pkg { margin:0 0 12px; padding:11px 14px; border-radius:10px; font-size:13px;
    color:#1d4ed8; background:rgba(37,99,235,.08); border:1px solid rgba(37,99,235,.28); }
  .pkg .pkghead { display:flex; align-items:center; gap:8px; margin-bottom:8px; line-height:1.5; word-break:break-all; }
  .pkg .pkgic { flex:0 0 auto; }
  .pkg .pkgtrack { height:6px; border-radius:3px; background:rgba(37,99,235,.18); overflow:hidden; }
  .pkg .pkgtrack i { display:block; height:100%; width:0; border-radius:3px;
    background:linear-gradient(90deg,#2563eb,#06b6d4); transition:width .25s ease; }
  .pkg.ok { color:#15803d; background:rgba(22,163,74,.10); border-color:rgba(22,163,74,.32); }
  .pkg.ok .pkgtrack i { background:linear-gradient(90deg,#16a34a,#22c55e); }
  .pkg.err { color:#dc2626; background:rgba(220,38,38,.09); border-color:rgba(220,38,38,.30); }
  .pkg.err .pkgtrack i { background:#dc2626; }
  #live { font-size:12px; color:var(--mut); display:inline-flex; align-items:center; gap:5px; user-select:none; }
  #live .dot { width:8px; height:8px; border-radius:50%; background:#cbd5e1; transition:background .2s ease; flex:0 0 auto; }
  #live.on .dot { background:#16a34a; }
  #live.tmp .dot { background:#f59e0b; }
  @keyframes liveFlash { 0% { background:rgba(37,99,235,.16); } 100% { background:transparent; } }
  tbody tr.flash td { animation:liveFlash 1s ease both; }
  /* ---- 视图切换工具栏 ---- */
  #toolbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin:0 0 10px; }
  #toolbar .views { display:inline-flex; border:1px solid var(--bd); border-radius:9px; overflow:hidden; background:var(--card,#fff); }
  #toolbar .views button { background:none; border:0; padding:6px 11px; font-size:13px; color:var(--mut); cursor:pointer;
    display:inline-flex; align-items:center; gap:5px; border-right:1px solid var(--bd); }
  #toolbar .views button:last-child { border-right:0; }
  #toolbar .views button:hover { background:rgba(37,99,235,.07); color:var(--accent,#2563eb); }
  #toolbar .views button.on { background:var(--accent,#2563eb); color:#fff; }
  #toolbar .zoom { display:inline-flex; align-items:center; gap:7px; font-size:13px; color:var(--mut); }
  #toolbar .zoom input[type=range] { width:120px; accent-color:var(--accent,#2563eb); }
  #toolbar .zoom .sizelabel { min-width:52px; font-variant-numeric:tabular-nums; }
  /* ---- 批量选择 ---- */
  #toolbar .selbar { display:inline-flex; align-items:center; gap:8px; font-size:13px; color:var(--mut); }
  #toolbar .selbar .cnt { color:var(--accent,#2563eb); font-weight:600; font-variant-numeric:tabular-nums; }
  #toolbar .selbar button { font-size:13px; color:var(--accent,#2563eb); background:none; border:1px solid var(--bd);
    border-radius:8px; padding:5px 11px; cursor:pointer; }
  #toolbar .selbar button:hover { background:rgba(37,99,235,.07); }
  #toolbar .selbar button:disabled { opacity:.45; cursor:not-allowed; }
  #toolbar .selbar button.primary { background:var(--accent,#2563eb); color:#fff; border-color:var(--accent,#2563eb); }
  #toolbar .selbar button.primary:hover { filter:brightness(1.06); background:var(--accent,#2563eb); }
  /* 表格里的勾选列 */
  th.selcol, td.selcol { width:34px; text-align:center; padding-left:8px; padding-right:0; }
  td.selcol input[type=checkbox], th.selcol input[type=checkbox] { width:15px; height:15px; cursor:pointer;
    accent-color:var(--accent,#2563eb); vertical-align:middle; }
  tr.picked { background:rgba(37,99,235,.07); }
  tr.picked td { background:rgba(37,99,235,.07); }
  /* 网格里的勾选角标 */
  .cell .pick { position:absolute; top:6px; left:6px; z-index:2; display:flex; }
  .cell .pick input[type=checkbox] { width:16px; height:16px; cursor:pointer; accent-color:var(--accent,#2563eb);
    box-shadow:0 1px 4px rgba(0,0,0,.28); border-radius:3px; }
  .cell.picked { border-color:var(--accent,#2563eb); box-shadow:0 0 0 2px rgba(37,99,235,.35); }
  /* ---- 网格视图(图标/平铺/缩略图共用) ---- */
  #grid { display:none; grid-template-columns:repeat(auto-fill,minmax(var(--cell,132px),1fr)); gap:12px; }
  #grid.on { display:grid; }
  body.view-icons #grid, body.view-tiles #grid, body.view-thumbs #grid { display:grid; }
  body.view-icons #list, body.view-tiles #list, body.view-thumbs #list { display:none; }
  body.view-list #grid { display:none; }
  .cell { position:relative; border:1px solid var(--bd); border-radius:10px; background:var(--card,#fff); overflow:hidden;
    display:flex; flex-direction:column; transition:box-shadow .15s ease, border-color .15s ease, transform .15s ease; }
  .cell:hover { box-shadow:0 6px 16px rgba(15,23,42,.12); border-color:#bcd3ff; }
  body.view-icons .cell { padding:10px 8px; align-items:center; }
  body.view-tiles .cell { padding:10px; }
  body.view-thumbs .cell { padding:0; }
  .cell .thumb { width:100%; aspect-ratio:1/1; display:flex; align-items:center; justify-content:center;
    background:repeating-conic-gradient(#f1f3f6 0% 25%, #e7eaef 0% 50%) 50%/16px 16px; overflow:hidden; cursor:zoom-in; }
  .cell .thumb img { width:100%; height:100%; object-fit:cover; display:block; opacity:0; transition:opacity .2s ease; }
  .cell .thumb img.loaded { opacity:1; }
  .cell .thumb .ph { font-size:38px; line-height:1; user-select:none; }
  body.view-thumbs .cell .thumb { cursor:zoom-in; }
  .cell .meta { padding:7px 9px; min-width:0; }
  body.view-icons .cell .meta { padding:7px 2px 0; text-align:center; width:100%; }
  .cell .fname { font-size:12.5px; word-break:break-all; line-height:1.35; max-height:2.7em; overflow:hidden; }
  .cell .fname.link a { color:inherit; text-decoration:none; }
  .cell .fname.link a:hover { text-decoration:underline; }
  .cell .sub { font-size:11px; color:var(--mut); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  body.view-icons .cell .sub { text-align:center; }
  .cell.dir { cursor:pointer; }
  .cell .cacts { position:absolute; top:6px; right:6px; display:flex; gap:4px; opacity:0; transition:opacity .15s ease; }
  .cell:hover .cacts { opacity:1; }
  .cell .cacts button { background:rgba(255,255,255,.94); border:1px solid var(--bd); border-radius:6px; font-size:11px;
    padding:2px 6px; cursor:pointer; color:var(--accent,#2563eb); }
  .cell .cacts button.danger { color:#dc2626; }
  .cell .cacts button:disabled { color:var(--mut); cursor:not-allowed; }
  .cell.flash { animation:cellFlash 1.1s ease both; }
  @keyframes cellFlash { 0% { box-shadow:0 0 0 3px rgba(37,99,235,.45); } 100% { box-shadow:0 0 0 0 rgba(37,99,235,0); } }
  /* ---- 大图预览(lightbox) ---- */
  #lightbox { position:fixed; inset:0; z-index:200; background:rgba(10,14,22,.92); display:none;
    align-items:center; justify-content:center; opacity:0; transition:opacity .18s ease; }
  #lightbox.open { display:flex; opacity:1; }
  /* 舞台铺满全屏用于“点空白处返回”,但四周要留出空间:
     下方给底栏让位,避免图片被底栏遮住;z-index 让控件浮在舞台之上。 */
  #lightbox .lb-stage { position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
    padding:52px 68px 72px; z-index:1; overflow:hidden; }
  /* 缩放容器:所有变换(缩放/拖动)都作用在它上面,内部的 low/hi 两张图始终同尺寸叠放。
     这样低清与高清切换时不会跳动,滚轮缩放也只影响容器。 */
  #lightbox .lb-zoom { position:relative; display:flex; align-items:center; justify-content:center;
    max-width:100%; max-height:100%; transform-origin:center center; transition:transform .06s linear; }
  #lightbox .lb-zoom.dragging { transition:none; cursor:grabbing; }
  #lightbox .lb-zoom.idle { cursor:zoom-in; }
  #lightbox img { max-width:100%; max-height:100%; object-fit:contain; box-shadow:0 10px 40px rgba(0,0,0,.5);
    border-radius:6px; cursor:inherit; background:#fff; }
  /* 低清预览图与高清原图叠放在同一位置(同尺寸),高清就位后低清淡出,避免闪烁与跳动 */
  #lightbox img.lb-low { position:absolute; inset:0; margin:auto; filter:blur(1px); opacity:.92;
    transition:opacity .26s ease; }
  #lightbox img.lb-low.fade { opacity:0; }
  /* 视频预览:用原生播放器,不参与图片缩放 */
  #lightbox video.lb-video { max-width:100%; max-height:100%; border-radius:8px; background:#000;
    box-shadow:0 10px 40px rgba(0,0,0,.55); outline:none; }
  #lightbox .lb-spin { color:#cbd5e1; font-size:14px; z-index:2; }
  #lightbox .lb-note { position:absolute; top:14px; left:50%; transform:translateX(-50%); z-index:4;
    color:#fde68a; background:rgba(120,53,15,.82); border:1px solid rgba(253,230,138,.35); border-radius:8px;
    padding:6px 13px; font-size:12.5px; max-width:82%; text-align:center; display:none; }
  #lightbox .lb-note.warn { display:block; }
  #lightbox .lb-note.err { display:block; color:#fecaca; background:rgba(127,29,29,.85); border-color:rgba(254,202,202,.35); }
  #lightbox .lb-bar { position:absolute; left:0; right:0; bottom:0; padding:10px 16px; display:flex; align-items:center;
    gap:10px; flex-wrap:wrap; color:#e5e7eb; background:linear-gradient(transparent, rgba(0,0,0,.62)); font-size:13px; z-index:3; }
  /* 底栏只让其中真正可点的控件拦截鼠标;栏内空白区域仍然“穿透”到舞台,
     这样在底栏空白处点击也能关闭预览,不会出现“点了没反应”的死区。 */
  #lightbox .lb-bar { pointer-events:none; }
  #lightbox .lb-bar > * { pointer-events:auto; }
  #lightbox .lb-bar .nm, #lightbox .lb-bar .idx, #lightbox .lb-bar .zoomlvl { pointer-events:none; }
  #lightbox .lb-bar .nm { flex:1 1 160px; min-width:0; word-break:break-all; }
  #lightbox .lb-bar .idx { color:#9ca3af; font-variant-numeric:tabular-nums; }
  #lightbox .lb-bar .zoomlvl { color:#cbd5e1; font-variant-numeric:tabular-nums; min-width:44px; text-align:center; }
  #lightbox .lb-bar a, #lightbox .lb-bar button { color:#e5e7eb; background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.22);
    border-radius:7px; padding:4px 10px; font-size:12.5px; cursor:pointer; text-decoration:none; white-space:nowrap; }
  #lightbox .lb-bar a:hover, #lightbox .lb-bar button:hover { background:rgba(255,255,255,.22); }
  #lightbox .lb-close { position:absolute; top:14px; right:16px; width:38px; height:38px; border-radius:50%;
    background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.24); color:#fff; font-size:19px; cursor:pointer;
    display:flex; align-items:center; justify-content:center; line-height:1; z-index:3; }
  #lightbox .lb-close:hover { background:rgba(255,255,255,.26); }
  #lightbox .lb-nav { position:absolute; top:50%; transform:translateY(-50%); width:44px; height:60px; border:0; cursor:pointer;
    background:rgba(255,255,255,.1); color:#fff; font-size:22px; display:flex; align-items:center; justify-content:center;
    border-radius:9px; z-index:3; }
  #lightbox .lb-nav:hover { background:rgba(255,255,255,.24); }
  #lightbox .lb-nav.prev { left:14px; }
  #lightbox .lb-nav.next { right:14px; }
  #lightbox .lb-nav[disabled] { opacity:.25; cursor:default; }
  @media (max-width:640px){ #lightbox .lb-stage { padding:48px 12px; } #lightbox .lb-nav { width:36px; height:48px; } }
  /* ---- 分享相关 ---- */
  .hdr-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .btn-sm { display:inline-flex; align-items:center; gap:6px; background:var(--card,#fff); color:var(--accent,#2563eb);
    border:1px solid #bcd3ff; border-radius:8px; padding:6px 12px; font-size:13px; cursor:pointer; white-space:nowrap; }
  .btn-sm:hover { background:#f3f7ff; }
  .btn-sm .cnt { background:#2563eb; color:#fff; border-radius:9px; font-size:11px; line-height:1; padding:3px 6px; }
  .btn-sm[disabled] { opacity:.45; cursor:not-allowed; }
  #sharePanel { display:none; }
  #sharePanel.open { display:block; }
  .panel { border:1px solid var(--bd); border-radius:10px; background:var(--card,#fff); margin-bottom:14px; overflow:hidden; }
  .panel h2 { font-size:14px; margin:0; padding:10px 14px; border-bottom:1px solid var(--bd); background:var(--th,#fafbfc);
    display:flex; align-items:center; gap:8px; font-weight:600; }
  .panel h2 .sub { font-weight:400; color:var(--mut); font-size:12px; }
  .panel .body { padding:12px 14px; }
  .sh-item { display:flex; align-items:flex-start; gap:12px; padding:11px 0; border-bottom:1px solid var(--bd); flex-wrap:wrap; }
  .sh-item:last-child { border-bottom:0; }
  .sh-item .info { flex:1 1 260px; min-width:0; }
  .sh-item .nm { font-size:14px; font-weight:600; word-break:break-all; }
  .sh-item .meta { font-size:12px; color:var(--mut); margin-top:3px; }
  .sh-item .urls { margin-top:6px; display:flex; flex-direction:column; gap:3px; }
  .sh-url { display:inline-flex; align-items:center; gap:6px; font-size:12.5px; }
  .sh-url code { background:rgba(37,99,235,.08); border-radius:5px; padding:2px 6px; font-family:ui-monospace,Consolas,monospace;
    word-break:break-all; }
  .sh-url button { font-size:12px; padding:1px 7px; }
  .sh-item .ops { display:flex; gap:6px; flex-wrap:wrap; }
  .tag { font-size:11px; border-radius:6px; padding:2px 7px; background:rgba(37,99,235,.1); color:#2563eb; }
  .tag.lock { background:rgba(217,119,6,.12); color:#b45309; }
  .tag.free { background:rgba(22,163,74,.12); color:#15803d; }
  .empty-hint { color:var(--mut); font-size:13px; padding:6px 0; }
  /* 弹窗 */
  .modal-mask { position:fixed; inset:0; background:rgba(15,23,42,.42); display:flex; align-items:center; justify-content:center;
    padding:20px; z-index:100; opacity:0; pointer-events:none; transition:opacity .16s ease; }
  .modal-mask.open { opacity:1; pointer-events:auto; }
  .modal { background:var(--card,#fff); border-radius:12px; box-shadow:0 18px 50px rgba(0,0,0,.28); width:100%; max-width:440px;
    transform:translateY(-8px) scale(.985); transition:transform .16s ease; max-height:90vh; overflow:auto; }
  .modal-mask.open .modal { transform:none; }
  .modal h3 { margin:0; padding:14px 18px; font-size:15px; border-bottom:1px solid var(--bd); }
  .modal .mbody { padding:16px 18px; }
  .modal .mfoot { padding:12px 18px; border-top:1px solid var(--bd); display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; }
  .field { margin-bottom:13px; }
  .field label { display:block; font-size:13px; margin-bottom:5px; color:var(--mut); }
  .field input[type=text], .field input[type=password], .field input[type=number] { width:100%; padding:8px 10px; font-size:14px;
    border:1px solid var(--bd); border-radius:8px; background:var(--bg,#fff); color:inherit; }
  .field input:focus { outline:2px solid rgba(37,99,235,.35); border-color:var(--accent,#2563eb); }
  .field .hintline { font-size:12px; color:var(--mut); margin-top:5px; }
  .pathbox { font-family:ui-monospace,Consolas,monospace; font-size:13px; background:rgba(37,99,235,.07); border-radius:8px;
    padding:9px 11px; word-break:break-all; }
  .modal .msg { font-size:13px; margin-top:10px; min-height:17px; }
  .modal .msg.err { color:#dc2626; }
  .modal .msg.ok { color:#15803d; }
  #logPanel .panel .body { max-height:320px; overflow:auto; padding:0; }
  .log-row { display:flex; gap:10px; padding:7px 14px; border-bottom:1px solid var(--bd); font-size:12.5px; align-items:baseline; flex-wrap:wrap; }
  .log-row:last-child { border-bottom:0; }
  .log-row .t { color:var(--mut); font-family:ui-monospace,Consolas,monospace; flex:0 0 auto; }
  .log-row .a { flex:0 0 84px; color:var(--accent,#2563eb); }
  .log-row.bad .a { color:#dc2626; }
  .log-row .w { flex:0 0 auto; color:var(--fg,#1f2328); }
  .log-row .d { color:var(--mut); flex:1 1 140px; word-break:break-all; }
  @media (max-width:640px){ .mtime{ display:none; } header h1{ min-width:100%; } .log-row .a{ flex-basis:auto; } }
</style>
</head>
<body>
<header>
  <h1>📁 __TITLE__</h1>
  <span id="live" title="实时同步:共享目录或其它设备的改动会自动显示"><span class="dot"></span><span id="liveText">连接中…</span></span>
  <span class="hdr-actions" id="hdrActions" style="display:none">
    <button class="btn-sm" id="btnSharePanel" type="button" title="查看与管理已单独分享的文件夹">🔗 单独分享 <span class="cnt" id="shareCnt" style="display:none">0</span></button>
    <button class="btn-sm" id="btnPwdPanel" type="button" title="设置局域网访问本共享根所需的密码">🔒 访问密码</button>
    <button class="btn-sm" id="btnLog" type="button" title="查看最近的操作日志">📋 操作日志</button>
  </span>
  <span id="headerPath" style="color:var(--mut);font-size:13px"></span>
</header>
<main>
  <nav id="crumb"></nav>

  <section id="sharePanel" class="panel">
    <h2>🔗 单独分享的文件夹 <span class="sub">把某个文件夹单独开一个端口对外共享;仅本机可管理,已分享的文件夹内不能再分享</span></h2>
    <div class="body" id="shareList"><div class="empty-hint">加载中…</div></div>
    <div class="body" style="border-top:1px solid var(--bd)">
      <button class="btn-sm" id="btnPickFolder" type="button" title="浏览本机磁盘,选择共享根之外的文件夹来分享">📂 分享本机其他文件夹…</button>
      <span class="hintline" style="margin-left:8px">用于共享「共享根」以外的目录(如 D:/照片);仅本机可操作。</span>
    </div>
  </section>

  <section id="logPanel" class="panel" style="display:none">
    <h2>📋 最近操作日志 <span class="sub" id="logSub"></span></h2>
    <div class="body" id="logList"><div class="log-row"><span class="d">加载中…</span></div></div>
  </section>

  <section id="pwdPanel" class="panel" style="display:none">
    <h2>🔒 根目录访问密码 <span class="sub">开启后,局域网设备打开本页要先输入密码;本机访问免输</span></h2>
    <div class="body">
      <div id="pwdState" class="empty-hint">加载中…</div>
      <div class="field" style="margin-top:12px">
        <label>新密码(留空则不修改)</label>
        <input type="password" id="pwdNew" placeholder="建议 8 位以上,别用太简单的" autocomplete="new-password">
        <label style="margin-top:9px">再输一次</label>
        <input type="password" id="pwdNew2" placeholder="两次输入需一致" autocomplete="new-password">
        <div class="hintline">
          密码以 scrypt 哈希保存在本目录的 <code>rootauth.json</code>(不存明文);
          保存后<b>立即生效</b>,重启服务也依然有效。忘记密码时删掉该文件即可关闭密码保护。
        </div>
        <div class="hintline">
          只有<b>主共享</b>(本页)受它保护;「单独分享」的文件夹另有各自的口令,不受影响。
        </div>
      </div>
      <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center">
        <button class="btn-sm" id="pwdSave" type="button">保存密码</button>
        <button class="btn-sm" id="pwdClear" type="button">取消密码保护</button>
        <span class="hintline" id="pwdMsg"></span>
      </div>
    </div>
  </section>

  <div id="drop">
    <button class="btn-lg" id="pickFiles" type="button"><span class="up-ic">📄</span> 选择文件上传</button>
    <button class="btn-lg ghost" id="pickFolder" type="button"><span class="up-ic">📂</span> 上传文件夹</button>
    <span class="hint">或把文件 / 文件夹直接<b>拖</b>到灰色区域</span>
    <input type="file" id="fileInput" multiple hidden>
    <input type="file" id="dirInput" webkitdirectory multiple hidden>
  </div>
  <div id="uploading"></div>
  <div id="pkgBox" class="pkg" style="display:none">
    <div class="pkghead"><span class="pkgic">📦</span><span id="pkgText">准备中…</span></div>
    <div class="pkgtrack"><i id="pkgBar"></i></div>
  </div>

  <div id="toolbar">
    <span class="views" id="viewSwitch">
      <button type="button" data-view="list" title="详细列表">☰ 列表</button>
      <button type="button" data-view="icons" title="图标">▦ 图标</button>
      <button type="button" data-view="tiles" title="平铺">▤ 平铺</button>
      <button type="button" data-view="thumbs" title="大缩略图">🖼 缩略图</button>
    </span>
    <span class="zoom" id="zoomBox">
      <span>图标大小</span>
      <input type="range" id="zoomRange" min="96" max="280" step="8" value="132">
      <span class="sizelabel" id="zoomLabel">132 px</span>
    </span>
    <span class="selbar" id="newBar">
      <button type="button" id="btnNewFolder" title="在当前目录下新建一个文件夹">＋ 新建文件夹</button>
    </span>
    <span class="selbar" id="selBar">
      <span>已选 <span class="cnt" id="selCount">0</span> 项</span>
      <button type="button" id="selAll">全选</button>
      <button type="button" id="selNone" disabled>清空</button>
      <button type="button" id="selZip" class="primary" disabled title="把选中的文件/文件夹打包成 ZIP 下载">⬇ 下载选中</button>
    </span>
  </div>

  <table id="list">
    <thead><tr><th class="selcol"><input type="checkbox" id="selAllHead" title="全选本页"></th><th class="icon"></th><th>名称</th><th class="size">大小</th><th class="mtime">修改时间</th><th class="acts">操作</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <div id="grid"></div>
  <div id="msg"></div>
</main>

<!-- 大图预览:点缩略图放大,点空白处返回,不跳转链接 -->
<div id="lightbox" role="dialog" aria-modal="true" aria-label="图片预览">
  <button class="lb-close" id="lbClose" type="button" title="关闭 (Esc)">✕</button>
  <button class="lb-nav prev" id="lbPrev" type="button" title="上一张 (←)">‹</button>
  <button class="lb-nav next" id="lbNext" type="button" title="下一张 (→)">›</button>
  <div class="lb-stage" id="lbStage"><div class="lb-spin">加载中…</div></div>
  <div class="lb-note" id="lbNote"></div>
  <div class="lb-bar">
    <span class="nm" id="lbName"></span>
    <span class="idx" id="lbIdx"></span>
    <button id="lbZoomOut" type="button" title="缩小 (滚轮向下 / -)">−</button>
    <span class="zoomlvl" id="lbZoomLvl">100%</span>
    <button id="lbZoomIn" type="button" title="放大 (滚轮向上 / +)">＋</button>
    <button id="lbZoomReset" type="button" title="恢复原始大小 (0)">1:1</button>
    <a id="lbOpen" href="#" target="_blank" rel="noopener">新窗口打开原图</a>
    <a id="lbDown" href="#">下载</a>
    <button id="lbClose2" type="button">关闭</button>
  </div>
</div>

<!-- 分享/口令弹窗 -->
<div class="modal-mask" id="shareModal">
  <div class="modal">
    <h3 id="smTitle">分享文件夹</h3>
    <div class="mbody">
      <div class="field">
        <label>要单独分享的文件夹</label>
        <div class="pathbox" id="smPath">/</div>
      </div>
      <div class="field" id="smAbsWrap" style="display:none">
        <label>本机文件夹的绝对路径</label>
        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap">
          <input type="text" id="smAbs" placeholder="例如 D:/照片 或 \\服务器\共享" style="flex:1 1 220px">
          <button class="btn-sm" id="smBrowse" type="button" title="打开 Windows 的文件夹选择框">浏览…</button>
        </div>
        <div class="hintline">
          点击「浏览…」会弹出系统自带的文件夹选择框(只在本机有效);
          若弹不出来(例如服务跑在无桌面会话里),可直接手动粘贴完整路径。
        </div>
        <div class="hintline" style="color:#b45309">
          ⚠ 该文件夹会被单独开一个端口对外共享,其内容(含子目录)会被访问者看到。
          不能选择整个磁盘或系统目录。
        </div>
      </div>
      <div class="field">
        <label>访问端口(留空自动分配空闲端口)</label>
        <input type="number" id="smPort" min="1024" max="65535" placeholder="自动分配">
        <div class="hintline">端口会单独建立一个 HTTPS 监听,功能与主目录一致。</div>
      </div>
      <div class="field">
        <label><input type="checkbox" id="smUsePwd"> 设置读写口令(可上传/删除/重命名)</label>
        <div id="smPwdWrap" style="display:none; margin-top:7px">
          <input type="password" id="smPwd" placeholder="请输入口令(可留空表示不设)" autocomplete="new-password">
        </div>
        <div class="hintline">不设口令时,任何能访问该端口的设备都可直接读写。</div>
      </div>
      <div class="field">
        <label><input type="checkbox" id="smUseRoPwd"> 设置只读口令(只能浏览、下载、预览)</label>
        <div id="smRoPwdWrap" style="display:none; margin-top:7px">
          <input type="password" id="smRoPwd" placeholder="请输入只读口令" autocomplete="new-password">
        </div>
        <div class="hintline">用只读口令访问的人看不到也点不动上传/删除/重命名(服务端也会拒绝)。两个口令不能相同。</div>
      </div>
      <div class="msg" id="smMsg"></div>
    </div>
    <div class="mfoot">
      <button class="btn-ghost" id="smCancel" type="button">取消</button>
      <button class="btn-sub" id="smOk" type="button">开始分享</button>
    </div>
  </div>
</div>

<!-- 分享成功 / 地址展示弹窗 -->
<div class="modal-mask" id="addrModal">
  <div class="modal">
    <h3 id="amTitle">分享已开启</h3>
    <div class="mbody">
      <div class="pathbox" id="amPath"></div>
      <div class="field" style="margin-top:13px">
        <label>访问地址(把这个地址发给别人)</label>
        <div class="urls" id="amUrls"></div>
      </div>
      <div class="msg ok" id="amNote"></div>
    </div>
    <div class="mfoot">
      <button class="btn-sub" id="amClose" type="button">知道了</button>
    </div>
  </div>
</div>

<script>
"use strict";
const $ = (id) => document.getElementById(id);
let cur = "";          // 当前目录(相对根,"" 表示根)
let uploading = 0;
let extraBusy = 0;     // 重命名/删除等本地写操作的进行中计数,用于避免“静默刷新”撞上用户操作
let dirty = false;     // 收到变更但因本地操作繁忙被暂缓,忙完后再补一次刷新
let loadedOnce = false;// 首次渲染完成前不提示“已同步”
let sigPrev = new Map();// 上一次渲染的条目指纹,用于高亮刚变化的行
let lastEntries = [];  // 最近一次列目录的条目,供网格视图与预览切换使用
let viewMode = 'list'; // list | icons | tiles | thumbs
let cellSize = 132;    // 网格视图的单元格最小宽度(像素)
// 这两个开关由服务端渲染页面时注入(见 renderPage);必须声明在使用它们的 render() 之前
const CAN_SHARE = __CAN_SHARE__;
const IS_MAIN = __IS_MAIN__;
const READONLY = __READONLY__;   // 用只读口令访问:隐藏所有写操作入口
let sharesCache = [];  // 当前已单独分享的文件夹列表
let picked = new Set(); // 批量下载:已勾选的条目(当前目录内的相对路径)

/** 更新「已选 N 项」与按钮可用状态。 */
function syncSelBar(){
  const n = picked.size;
  const cnt = $("selCount"); if(cnt) cnt.textContent = String(n);
  const bZip = $("selZip"); if(bZip) bZip.disabled = n === 0;
  const bNone = $("selNone"); if(bNone) bNone.disabled = n === 0;
  // 表头勾选框反映“当前是否全部选中”
  const head = $("selAllHead");
  if(head){
    const total = lastEntries.length;
    head.checked = total > 0 && picked.size === total;
    head.indeterminate = picked.size > 0 && picked.size < total;
  }
}
/** 切换某个条目的勾选状态。 */
function togglePick(rel, on){
  if(on) picked.add(rel); else picked.delete(rel);
  renderPickedState();   // 同步行/格子的高亮样式(否则用户看不出选中了哪些)
  syncSelBar();
}
/** 勾选/取消勾选当前目录的全部条目。 */
function pickAll(on){
  picked = on ? new Set(lastEntries.map(e=>cur ? cur+"/"+e.name : e.name)) : new Set();
  renderPickedState();
  syncSelBar();
}
/** 只更新行/格子的勾选视觉,不重建整个列表(避免打断动画与滚动位置)。 */
function renderPickedState(){
  for(const tr of document.querySelectorAll("#rows tr")){
    const cb = tr.querySelector("td.selcol input");
    if(!cb) continue;
    const on = picked.has(cb.dataset.rel);
    cb.checked = on;
    tr.classList.toggle("picked", on);
  }
  for(const cell of document.querySelectorAll("#grid .cell")){
    const cb = cell.querySelector(".pick input");
    if(!cb) continue;
    const on = picked.has(cb.dataset.rel);
    cb.checked = on;
    cell.classList.toggle("picked", on);
  }
}
/**
 * 打包下载选中项(两段式):
 *   1. 先请服务端打包(大目录可能耗时几十秒),期间显示进度;
 *   2. 打完再触发浏览器下载 —— 此时走的是一个普通文件 URL,支持 Range 断点续传,
 *      所以断网/暂停后可以接着下,不会整包重来。
 */
/* ---------- 打包下载的进度提示 ---------- */
// 打包大目录可能要很久,必须给出明确反馈,否则用户以为卡死了会重复点。
function pkgHide(delay){
  const box = $("pkgBox");
  if(!box) return;
  setTimeout(()=>{ box.style.display = "none"; }, delay || 0);
}
function pkgSet(pct, text, cls){
  const bar = $("pkgBar");
  if(bar) bar.style.width = Math.max(0, Math.min(100, pct)) + "%";
  // 显示面板:面板初始是 display:none,只改 className 是显示不出来的(这里踩过一次坑)
  const box = $("pkgBox");
  if(box){ box.style.display = ""; box.className = "pkg" + (cls ? " " + cls : ""); }
  if(text) $("pkgText").textContent = text;
}

/**
 * 打包下载选中项(两段式):
 *   1. 先请服务端打包(大目录可能耗时很久),期间显示进度;
 *   2. 打完再触发浏览器下载 —— 此时走的是一个普通文件 URL,支持 Range 断点续传,
 *      所以断网/暂停后可以接着下,不会整包重来。
 */
async function downloadPicked(){
  if(!picked.size){ msg("请先勾选要下载的文件或文件夹", true); return; }
  const list = [...picked];
  const btn = $("selZip");
  if(btn){ btn.disabled = true; }
  msg("");
  pkgSet(3, "正在准备打包 "+list.length+" 项…");

  try{
    const r = await fetch("/api/download-zip/prepare?dir="+enc(cur)+"&paths="+enc(list.join("\\n")), { method:"POST" });
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error || ("HTTP "+r.status));
    const id = j.id;

    // 服务端已在后台打包,这里轮询进度;打包完再触发下载
    const t0 = Date.now();
    let tick = 0;
    for(;;){
      const sr = await fetch("/api/download-zip/status?id="+enc(id));
      const sj = await sr.json().catch(()=>({}));
      if(!sr.ok) throw new Error(sj.error || ("HTTP "+sr.status));
      if(sj.error) throw new Error(sj.error);
      if(sj.ready) break;
      const added = sj.added || 0;
      const total = sj.items || list.length;
      const secs = Math.round((Date.now()-t0)/1000);
      // 进度条:打包阶段文件数会增长,取「已处理/总数」;总数未知时用爬行动画表示在干活
      const pct = total > 0 ? Math.min(96, 5 + Math.round(added / total * 90)) : Math.min(90, 5 + (tick += 2));
      pkgSet(pct, "正在打包… 已处理 "+added+" 项 / 共 "+total+" 项 · 已用 "+secs+" 秒" +
        (secs >= 20 ? "(大目录请耐心等待,完成后会自动开始下载)" : ""));
      await new Promise(res=>setTimeout(res, 700));
    }

    // 打包完成:用隐藏 iframe 触发下载(不离开当前页,也不会被当成弹窗拦截)。
    // 这个 URL 支持 Range,浏览器下载管理器里可以暂停/继续。
    pkgSet(100, "打包完成,正在开始下载:"+ (j.name || "压缩包"), "ok");
    const url = "/api/download-zip/get?id="+enc(id);
    const fr = document.createElement("iframe");
    fr.style.display = "none";
    fr.src = url;
    document.body.appendChild(fr);
    setTimeout(()=>fr.remove(), 30*60*1000);
    msg("已开始下载:"+ (j.name || "压缩包") + "(若中断可在浏览器下载列表里继续)");
    pkgHide(4000);
  }catch(e){
    pkgSet(100, "打包失败: "+e.message, "err");
    msg("打包失败: "+e.message, true);
    pkgHide(6000);
  }finally{
    if(btn){ btn.disabled = picked.size === 0; }
  }
}

function enc(p){ return encodeURIComponent(p); }
function qs(p){ return "?path=" + enc(p); }
function fmtSize(n){
  if(n==null) return "";
  if(n<1024) return n+" B";
  const u=["KB","MB","GB","TB"]; let v=n,i=-1;
  do{v/=1024;i++;}while(v>=1024&&i<u.length-1);
  return (v>=100?v.toFixed(0):v.toFixed(1))+" "+u[i];
}
function fmtTime(t){
  if(!t) return "";
  const d=new Date(t),p=(x)=>String(x).padStart(2,"0");
  return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes());
}
function nav(p){
  if(typeof p!=="string") return;
  cur = p.replace(/\\\\/g,"/").replace(/^\\/+|\\/+$/g,"");
  load();
}
function gotoDir(p){ cur=p; load(); }

async function load(){
  try{
    const r = await fetch("/api/list" + qs(cur));
    const j = await r.json();
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    if(typeof j.publish === "string" && j.publish !== cur) cur = j.publish; // 与服务端归一化后的路径保持一致
    render(j);
    syncLightbox();
    loadedOnce = true;
    // 刷新完成后必须把状态恢复成“已同步”;否则一次变更就会让状态永久停在“同步中…”。
    setLive("on");
  }catch(e){
    $("rows").innerHTML="";
    msg("加载目录失败: "+e.message, true);
    setLive("off");
  }
}

/**
 * 目录内容变化后,若大图预览正开着:
 * 图片还在就保持展示(刷新切换列表),图片已被外部删除则自动关闭,避免停在破图上。
 */
function syncLightbox(){
  if(!$("lightbox").classList.contains("open")) return;
  const current = lbList[lbIndex];
  const fresh = lbImagesInDir();
  if(!current || !fresh.some(x=>x.rel===current.rel)){
    closeLightbox();
    return;
  }
  lbList = fresh;
  lbIndex = Math.max(0, fresh.findIndex(x=>x.rel===current.rel));
  showLightbox();
}

/* ---------- 实时静默同步 ---------- */
// 服务器通过 SSE 推送共享目录变更;收到后静默重载当前目录,不打断输入、不重载整个页面。
function busy(){ return uploading > 0 || extraBusy > 0; }
function beginBusy(){ extraBusy++; }
function endBusy(){
  if(extraBusy > 0) extraBusy--;
  if(extraBusy === 0 && uploading === 0 && dirty){ dirty = false; load(); }
}
function setLive(state){
  const el=$("live"); if(!el) return;
  el.className = state === "on" ? "on" : (state === "tmp" ? "tmp" : "");
  $("liveText").textContent = state === "on" ? "已同步" : (state === "tmp" ? "同步中…" : "已断开");
}
function onRemoteChange(){
  if(busy()){ dirty = true; return; }     // 本地正在上传/改名/删除:忙完再刷新
  load();
}
function connectLive(){
  if(!window.EventSource){ setLive("off"); return; }
  const es = new EventSource("/api/events");   // 断线时浏览器会自动重连
  es.addEventListener("open", ()=>{ setLive("on"); if(dirty && !busy()){ dirty=false; load(); } });
  es.addEventListener("change", ()=>{ if(loadedOnce) setLive("tmp"); onRemoteChange(); });
  es.addEventListener("error", ()=>setLive("off"));
}

function render(j){
  $("headerPath").textContent = "共享目录: " + (j.dir ? "/"+j.dir : "/");
  // 本次刷新相对上一次,哪些条目是新增/变化的 —— 用于“静默同步”时轻量高亮
  const sig = new Map(j.entries.map(e=>[e.name, e.isDir?0:e.size+"@"+e.mtime]));
  const diff = loadedOnce && sigPrev.size > 0;
  const changed = (n)=>{ if(!diff) return false; const p = sigPrev.get(n); return p === undefined || p !== sig.get(n); };
  sigPrev = sig;
  // 面包屑
  const crumb = $("crumb");
  crumb.textContent="";
  const mk=(label,path,isLast)=>{
    const s=document.createElement("span");
    if(isLast){ s.textContent=label; }
    else{ const a=document.createElement("a"); a.href="#"; a.textContent=label;
      a.addEventListener("click",(ev)=>{ ev.preventDefault(); gotoDir(path); }); s.appendChild(a); }
    crumb.appendChild(s);
    if(!isLast){ const sep=document.createElement("span"); sep.className="sep"; sep.textContent=" / "; crumb.appendChild(sep); }
  };
  mk("根目录","",cur==="");
  for(const c of j.crumbs) mk(c.name,c.path, c.path===cur);

  // 行
  lastEntries = j.entries;
  // 切换目录后清空勾选(勾选是「当前目录内」的概念,跨目录保留会造成误解)
  picked.clear();
  const tbody=$("rows"); tbody.textContent="";
  const grid=$("grid"); grid.textContent="";
  if(!j.entries.length){
    const tr=document.createElement("tr");
    const td=document.createElement("td"); td.colSpan=6; td.className="empty"; td.textContent="(空目录)";
    tr.appendChild(td); tbody.appendChild(tr); syncSelBar(); return;
  }
  for(const e of j.entries){
    const tr=document.createElement("tr");
    if(changed(e.name)) tr.classList.add("flash");
    const full = cur ? cur+"/"+e.name : e.name;
    // 勾选列(批量下载用)
    const td0=document.createElement("td"); td0.className="selcol";
    const cb=document.createElement("input"); cb.type="checkbox"; cb.dataset.rel=full;
    cb.title="勾选后可批量打包下载";
    cb.addEventListener("click",(ev)=>ev.stopPropagation());
    cb.addEventListener("change",()=>togglePick(full, cb.checked));
    td0.appendChild(cb);
    // 图标(图片显示缩略图;视频显示封面帧)
    const td1=document.createElement("td"); td1.className="icon";
    const isPic = isImageName(e.name);
    const isVid = isVideoName(e.name);
    if(!e.isDir && (isPic || isVid)){
      const im=document.createElement("img"); im.className="rowthumb"; im.loading="lazy";
      im.alt="";
      im.addEventListener("error",()=>{
        // 图片:回退加载原图;视频:回退为图标(视频不能当图片显示)
        if(isPic && !im.dataset.fellback){ im.dataset.fellback="1"; im.src="/raw"+qs(full)+"&inline=1"; return; }
        im.replaceWith(document.createTextNode(isVid ? "🎬" : "🖼"));
      });
      im.src="/thumb"+qs(full);
      im.addEventListener("click",(ev)=>{ ev.preventDefault(); ev.stopPropagation(); openLightbox(full,e.name); });
      td1.appendChild(im);
    } else {
      td1.textContent = e.isDir ? "📁" : "📄";
    }
    // 名称
    const td2=document.createElement("td"); td2.className="name";
    const a=document.createElement("a"); a.textContent=e.name;
    if(e.isDir){ a.href="#"; a.addEventListener("click",(ev)=>{ev.preventDefault();gotoDir(full);}); tr.classList.add("dir-row"); }
    else{ a.href="/download"+qs(full); }
    td2.appendChild(a);
    // 大小
    const td3=document.createElement("td"); td3.className="size"; td3.textContent=e.isDir?"":fmtSize(e.size);
    // 时间
    const td4=document.createElement("td"); td4.className="mtime"; td4.textContent=fmtTime(e.mtime);
    // 操作
    const td5=document.createElement("td"); td5.className="acts";
    if(!e.isDir){
      const dv=document.createElement("a"); dv.href="/download"+qs(full); dv.textContent="下载";
      td5.appendChild(dv);
      // 列表里不再放「预览」按钮:图片点缩略图放大,其它类型可在名称处查看
    }
    // 重命名 / 删除(只读口令下不显示;服务端也会拒绝)
    if(!READONLY){
      const rm=document.createElement("button"); rm.textContent="重命名"; rm.addEventListener("click",(ev)=>{ev.stopPropagation();renameEntry(full,e.isDir);});
      td5.appendChild(rm);
    }
    // 目录行额外给一个「分享」入口:把该文件夹单独开一个端口(仅主端口、仅本机可用)
    if(e.isDir && CAN_SHARE){
      const bSh=document.createElement("button"); bSh.textContent="分享";
      bSh.title = isSharedOrInside(full) ? "该文件夹已在某个单独分享范围内,不能重复分享"
                                         : "把这个文件夹单独开一个端口对外共享";
      if(isSharedOrInside(full)){ bSh.disabled=true; bSh.style.opacity=".45"; bSh.style.cursor="not-allowed"; }
      bSh.addEventListener("click",(ev)=>{ ev.stopPropagation(); if(!bSh.disabled) openShareDialog(full,e.name); });
      td5.appendChild(bSh);
    }
    if(!READONLY){
      const del=document.createElement("button"); del.className="danger"; del.textContent="删除";
      del.addEventListener("click",(ev)=>{ev.stopPropagation();deleteEntry(full,e.isDir);});
      td5.appendChild(del);
    }
    tr.append(td0,td1,td2,td3,td4,td5);
    tbody.appendChild(tr);
  }

  // 网格视图(图标/平铺/缩略图共用同一份数据,仅样式不同)
  for(const e of j.entries){
    const full = cur ? cur+"/"+e.name : e.name;
    const cell=document.createElement("div");
    cell.className="cell"+(e.isDir?" dir":"");
    if(changed(e.name)) cell.classList.add("flash");
    // 勾选角标(批量下载用)
    const pickWrap=document.createElement("div"); pickWrap.className="pick";
    const pcb=document.createElement("input"); pcb.type="checkbox"; pcb.dataset.rel=full;
    pcb.title="勾选后可批量打包下载";
    pcb.addEventListener("click",(ev)=>ev.stopPropagation());
    pcb.addEventListener("change",()=>togglePick(full, pcb.checked));
    pickWrap.appendChild(pcb);
    cell.appendChild(pickWrap);
    const isPic = !e.isDir && isImageName(e.name);
    const isVid = !e.isDir && isVideoName(e.name);
    const thumb=document.createElement("div"); thumb.className="thumb";
    if(e.isDir){
      const ph=document.createElement("span"); ph.className="ph"; ph.textContent="📁";
      thumb.appendChild(ph);
      thumb.addEventListener("click",()=>gotoDir(full));
    } else if(isPic || isVid){
      // 图片用低清缩略图、视频用 ffmpeg 封面;lazy 让可视区外延后请求
      const im=document.createElement("img"); im.loading="lazy"; im.alt="";
      im.addEventListener("load",()=>im.classList.add("loaded"));
      im.addEventListener("error",()=>{
        // 图片可回退加载原图;视频没有封面就显示图标
        if(isPic && !im.dataset.fellback){
          im.dataset.fellback="1";
          im.src="/raw"+qs(full)+"&inline=1";
          return;
        }
        im.remove();
        const ph=document.createElement("span"); ph.className="ph"; ph.textContent=isVid ? "🎬" : "🖼";
        thumb.appendChild(ph);
      });
      im.src="/thumb"+qs(full);
      thumb.appendChild(im);
      thumb.addEventListener("click",()=>openLightbox(full,e.name));
    } else {
      const ph=document.createElement("span"); ph.className="ph"; ph.textContent=isInlineable(e.name)?"📄":"📦";
      thumb.appendChild(ph);
      thumb.addEventListener("click",()=>{ location.href="/download"+qs(full); });
    }
    const meta=document.createElement("div"); meta.className="meta";
    const fn=document.createElement("div"); fn.className="fname link";
    const fa=document.createElement("a"); fa.textContent=e.name; fa.title=e.name;
    if(e.isDir){ fa.href="#"; fa.addEventListener("click",(ev)=>{ev.preventDefault();gotoDir(full);}); }
    else{ fa.href="/download"+qs(full); }
    fn.appendChild(fa);
    const sub=document.createElement("div"); sub.className="sub";
    sub.textContent = e.isDir ? "文件夹" : (fmtSize(e.size)+" · "+fmtTime(e.mtime));
    meta.append(fn,sub);
    const cacts=document.createElement("div"); cacts.className="cacts";
    if(e.isDir && CAN_SHARE){
      const bSh=document.createElement("button"); bSh.textContent="分享"; bSh.title="单独开一个端口共享此文件夹";
      if(isSharedOrInside(full)){ bSh.disabled=true; }
      bSh.addEventListener("click",(ev)=>{ ev.stopPropagation(); if(!bSh.disabled) openShareDialog(full,e.name); });
      cacts.appendChild(bSh);
    }
    if(isPic){
      const bDl=document.createElement("button"); bDl.textContent="下载";
      bDl.addEventListener("click",(ev)=>{ ev.stopPropagation(); location.href="/download"+qs(full); });
      cacts.appendChild(bDl);
    }
    // 只读口令下不显示改名/删除(服务端同样会拒绝)
    if(!READONLY){
      const bRm=document.createElement("button"); bRm.textContent="改名";
      bRm.addEventListener("click",(ev)=>{ ev.stopPropagation(); renameEntry(full,e.isDir); });
      const bDel=document.createElement("button"); bDel.className="danger"; bDel.textContent="删除";
      bDel.addEventListener("click",(ev)=>{ ev.stopPropagation(); deleteEntry(full,e.isDir); });
      cacts.append(bRm,bDel);
    }
    cell.append(thumb,meta,cacts);
    grid.appendChild(cell);
  }
  syncSelBar();
}

async function mkdirRec(relPath){
  const r = await fetch("/api/mkdir?path="+enc(relPath), {method:"POST"});
  const j = await r.json();
  if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
}

/** 在当前目录下新建文件夹。 */
async function newFolder(){
  if(READONLY){ msg("只读访问不能新建文件夹", true); return; }
  const name = prompt("新建文件夹的名称:", "新建文件夹");
  if(name === null) return;                       // 取消
  const trimmed = name.trim();
  if(!trimmed){ msg("文件夹名称不能为空", true); return; }
  if(trimmed.includes("/") || trimmed.includes("\\\\")){ msg("名称不能包含 / 或 \\\\", true); return; }
  if(trimmed === "." || trimmed === ".."){ msg("名称不合法", true); return; }
  const target = cur ? cur + "/" + trimmed : trimmed;
  beginBusy();
  try{
    await mkdirRec(target);
    msg("已新建文件夹:" + escName(trimmed));
    await load();
  }catch(e){
    msg("新建文件夹失败: " + e.message, true);
  }finally{ endBusy(); }
}
function escName(n){ return String(n).replace(/[<>&"']/g,""); }
async function postM(rel){
  const r = await fetch(rel, { method:"POST" });
  return { ok:r.ok, status:r.status, j: await r.json().catch(()=>null) };
}
async function renameEntry(full,isDir){
  const oldName = full.split("/").pop();
  const newName = prompt("输入新的名称:", oldName);
  if(newName===null) return;                 // 取消
  if(!newName || newName.trim()===""){ msg("名称不能为空", true); return; }
  if(newName.includes("/")||newName.includes("\\\\")){ msg("名称不能包含 / 或 \\\\", true); return; }
  beginBusy();
  try{
    const {ok,status,j} = await postM("/api/rename?path="+enc(full)+"&to="+enc(newName.trim()));
    if(!ok){ msg(j&&j.error?j.error:("重命名失败 (HTTP "+status+")"), true); return; }
    msg("已重命名: "+escName(oldName)+" → "+escName(newName.trim()));
    await load();
  } finally { endBusy(); }
}
async function deleteEntry(full,isDir){
  let pre, extra;
  if(isDir){ pre='确定永久删除目录 "'+escName(full)+'" 吗？'; extra='\\n其全部内容将一并删除，此操作不可撤销。'; }
  else{ pre='确定永久删除文件 "'+escName(full)+'" 吗？'; extra='\\n此操作不可撤销。'; }
  if(!confirm(pre+extra)) return;
  beginBusy();
  try{
    const {ok,status,j} = await postM("/api/delete?path="+enc(full));
    if(!ok){ msg(j&&j.error?j.error:("删除失败 (HTTP "+status+")"), true); return; }
    msg("已删除: "+escName(full));
    await load();
  } finally { endBusy(); }
}

function msg(t,err){ const m=$("msg"); m.textContent=t; m.className=err?"err":""; }
function crumbPath(){ return cur; }

/* ---------- 上传(文件 / 文件夹) ---------- */
const drop=$("drop"), fileInput=$("fileInput"), dirInput=$("dirInput");
const pickFiles=$("pickFiles"), pickFolder=$("pickFolder");
// 两个按钮直接触发各自系统选择框(避免此前“点了没反应”)
pickFiles.addEventListener("click",(e)=>{ e.stopPropagation(); fileInput.click(); });
pickFolder.addEventListener("click",(e)=>{ e.stopPropagation(); dirInput.click(); });
fileInput.addEventListener("change",()=>{ if(fileInput.files.length) uploadFiles([...fileInput.files], false); fileInput.value=""; });
dirInput.addEventListener("change",()=>{ if(dirInput.files.length) uploadFiles([...dirInput.files], true); dirInput.value=""; });
["dragover","dragenter"].forEach(ev=>drop.addEventListener(ev,(e)=>{e.preventDefault();drop.classList.add("over");}));
["dragleave","drop"].forEach(ev=>drop.addEventListener(ev,(e)=>{e.preventDefault();drop.classList.remove("over");}));
drop.addEventListener("drop",(e)=>{
  if(e.dataTransfer&&e.dataTransfer.files.length){
    const fs=[...e.dataTransfer.files];
    const isFolder = fs.some(f=>f.webkitRelativePath);
    uploadFiles(fs, isFolder);
  }
});

async function uploadFiles(files, folderMode){
  if(!files.length) return;
  const box=$("uploading");
  // 目录上传需要确保各层目标目录存在;mkdirRec 可一次建多层链,失败(如该层已是同名文件)抛明确错误并仅使该文件失败,不影响同批次其它项
  const ensured = new Set();
  async function mdOrThrow(dirRel){
    if(dirRel === "") return;
    if(ensured.has(dirRel)) return;
    ensured.add(dirRel);
    await mkdirRec(dirRel);
  }
  const rows=[];
  for(const f of files){
    const d=document.createElement("div"); d.className="up-item";
    const b=document.createElement("span"); b.className="bar"; const i=document.createElement("i"); b.appendChild(i);
    // 展示路径(文件夹时显示 相对子路径 / 目录名,文件只看 name)
    const disp = f.webkitRelativePath ? f.webkitRelativePath : f.name;
    const t=document.createElement("span"); t.style.flex="0 0 220px"; t.textContent=escName(disp); t.title=disp;
    const p=document.createElement("span"); p.style.flex="0 0 auto"; p.style.minWidth="110px"; p.textContent="0%";
    d.append(b,t,p); box.appendChild(d);
    d.classList.add("appear");   // 新到条目“下拉淡入”
    rows.push({f,d,i,p,t});
  }
  msg("正在上传 "+rows.length+" 项…");
  uploading += rows.length;
  let okCount=0;
  await Promise.all(rows.map(async ({f,d,i,p,t})=>{
    try{
      // 计算目标目录:普通文件上传到当前目录;目录文件上传到 webkitRelativePath 去掉文件名所在的目录
      let dirRel = cur;
      if(f.webkitRelativePath){
        const parts = f.webkitRelativePath.split("/");
        parts.pop();                 // 去掉文件名,保留其在本地文件夹内的父目录链
        const sub = parts.join("/"); // 例如 "myRoot/sub"
        dirRel = cur ? (sub ? cur + "/" + sub : cur) : sub;
        await mdOrThrow(dirRel);     // 目录链不存在→递归创建;被同名文件占用→抛错仅使本项失败
      }
      const url="/api/upload?dir="+enc(dirRel)+"&name="+enc(f.name);
      // 大文件走分片上传(可断点续传 + 自动重试);小文件仍走一次性上传,减少往返
      const CHUNK_THRESHOLD = 4*1024*1024;   // 超过 4MB 才分片
      let uploaded = 0;
      const onProgress=(loaded)=>{ const pct=Math.min(100, Math.round(loaded/f.size*100));
        i.style.width=pct+"%"; p.textContent=pct+"%"; };
      if(f.size > CHUNK_THRESHOLD){
        uploaded = await uploadChunked(dirRel, f, onProgress, (txt)=>{ p.textContent=txt; });
      } else {
        await new Promise((resolve,reject)=>{
          const xhr=new XMLHttpRequest();
          xhr.open("POST",url);
          xhr.upload.onprogress=(e)=>{ if(e.lengthComputable) onProgress(e.loaded); };
          xhr.onload=()=>{ try{ const j=JSON.parse(xhr.responseText); if(xhr.status>=400) throw new Error((j&&j.error)||("HTTP "+xhr.status)); resolve(); }catch(e){ reject(e); } };
          xhr.onerror=()=>reject(new Error("网络错误"));
          xhr.send(f);
        });
      }
      okCount++; p.textContent="✓"; p.style.color="#16a34a";
    }catch(e){
      // 把失败原因直接呈现出来(不止悬停),便于一眼定位
      const why=(e&&e.message)||"失败";
      d.classList.add("err");
      p.textContent="✗"; p.style.color="#dc2626";
      if(t && t.textContent){ t.title=why; }
      // 在其下附加一行原因(不占上方动画空间)
      let r=d.querySelector(".why"); 
      if(!r){ r=document.createElement("span"); r.className="why"; d.appendChild(r); }
      r.textContent="原因: "+why;
      r.style.flex="1 0 100%"; r.style.color="#dc2626"; r.style.fontSize="12px";
      r.style.wordBreak="break-all";
      d.title=why;
    }
  }));
  uploading -= rows.length;
  msg(okCount===rows.length ? ("全部上传成功("+okCount+" 项)") : ("上传完成:"+okCount+"/"+rows.length+" 成功,失败项见右侧 ✗"));
  if(okCount) load();

  // 上传稳定后:成功条目平滑“收起上移”退场;失败条目(红)保留一段时间便于查看
  setTimeout(()=>{
    const okItems = [...box.querySelectorAll(".up-item:not(.err)")];
    okItems.forEach((el,i)=>{
      const h = Math.max(el.offsetHeight||30, 1);
      el.style.setProperty("--h", h+"px");
      el.style.animationDelay = (i*45)+"ms";
      el.classList.add("leave");
      setTimeout(()=>{ el.style.animationDelay="0ms"; el.remove(); }, 360+(i*45));
    });
  }, 1600);
  setTimeout(()=>{
    [...box.querySelectorAll(".up-item.err")].forEach((el)=>{
      el.style.setProperty("--h", Math.max(el.offsetHeight||30,1)+"px");
      el.classList.add("leave");
      setTimeout(()=>el.remove(), 340);
    });
  }, 9000);
}

/* ---------- 大文件分片上传(自适应分片 + 断点续传 + 自动重试) ---------- */
const UPLOAD_MIN_CHUNK = 256*1024;      // 最小分片 256KB
const UPLOAD_MAX_CHUNK = 8*1024*1024;   // 最大分片 8MB
const UPLOAD_MAX_RETRY = 6;             // 单个分片最多重试次数

/** 读一个分片的响应体(JSON);失败时抛出带 message 的错误。 */
function chunkPost(url, blob){
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();
    xhr.open("POST",url);
    xhr.timeout=120000;                  // 单分片 2 分钟;超时按可重试错误处理
    xhr.onload=()=>{
      let j=null; try{ j=JSON.parse(xhr.responseText); }catch(e){}
      if(xhr.status>=400) return reject(Object.assign(new Error((j&&j.error)||("HTTP "+xhr.status)),
        { status:xhr.status, retriable:xhr.status>=500||xhr.status===408||xhr.status===0 }));
      resolve(j||{});
    };
    xhr.onerror=()=>reject(Object.assign(new Error("网络错误"),{ retriable:true }));
    xhr.ontimeout=()=>reject(Object.assign(new Error("请求超时"),{ retriable:true }));
    xhr.onabort=()=>reject(Object.assign(new Error("已取消"),{ retriable:true }));
    xhr.send(blob);
  });
}

/**
 * 以分片方式上传一个大文件。返回已上传的总字节数。
 * 关键行为:
 *   - 先问服务端"已经收到多少",从断点继续(刷新页面/断网后同样有效);
 *   - 分片大小随实测速度自适应:快则放大(减少往返),慢则缩小(降低单片失败代价);
 *   - 失败自动重试,退避 0.5s→1s→2s→…;偏移不匹配(409)时以服务端进度为准重新对齐。
 */
async function uploadChunked(dirRel, file, onProgress, onText){
  const base = "/api/upload/chunk?dir="+enc(dirRel)+"&name="+enc(file.name)+"&size="+file.size;
  const finishUrl = "/api/upload/finish?dir="+enc(dirRel)+"&name="+enc(file.name)+"&size="+file.size;

  // 1) 询问断点
  let offset = 0;
  try{
    const r = await fetch("/api/upload/status?dir="+enc(dirRel)+"&name="+enc(file.name)+"&size="+file.size);
    const j = await r.json();
    if(r.ok && j.resumable && j.received>0 && j.received<file.size) offset = j.received;
  }catch(e){ /* 查不到就从头传 */ }
  if(offset>0 && onText) onText("续传 "+Math.round(offset/file.size*100)+"%");
  onProgress(offset);

  // 2) 逐片上传
  let chunkSize = 1024*1024;   // 起始 1MB
  while(offset < file.size){
    const end = Math.min(offset + chunkSize, file.size);
    const blob = file.slice(offset, end);
    const t0 = performance.now();
    let attempt = 0;
    let advanced = false;
    while(attempt <= UPLOAD_MAX_RETRY && !advanced){
      try{
        const j = await chunkPost(base+"&offset="+offset, blob);
        const now = Number(j.received);
        offset = Number.isFinite(now) && now>=offset ? now : end;
        advanced = true;
        // 自适应分片:按实测速度调整(目标约 2 秒一片),并限制在上下限内
        const ms = Math.max(1, performance.now()-t0);
        const speed = blob.size/(ms/1000);
        const target = Math.round(speed*2);
        chunkSize = Math.max(UPLOAD_MIN_CHUNK, Math.min(UPLOAD_MAX_CHUNK, Math.round((chunkSize*0.5)+(target*0.5))));
      }catch(e){
        // 偏移不匹配:以服务端返回的进度为准重新对齐(通常是上一次响应丢了)
        if(e.status===409 && typeof e.received==="number"){ offset=e.received; advanced=true; break; }
        attempt++;
        if(attempt>UPLOAD_MAX_RETRY || e.retriable===false) throw e;
        const wait = Math.min(8000, 500*Math.pow(2, attempt-1));
        if(onText) onText("重试 "+attempt+"/"+UPLOAD_MAX_RETRY);
        await new Promise(r=>setTimeout(r, wait));
      }
    }
    onProgress(offset);
  }

  // 3) 收尾:服务端原子改名落盘
  let lastErr=null;
  for(let i=0;i<=UPLOAD_MAX_RETRY;i++){
    try{
      const r = await fetch(finishUrl, { method:"POST" });
      const j = await r.json().catch(()=>({}));
      if(!r.ok) throw Object.assign(new Error((j&&j.error)||("HTTP "+r.status)),{ retriable:r.status>=500 });
      return offset;
    }catch(e){
      lastErr=e;
      if(!e.retriable) throw e;
      await new Promise(r=>setTimeout(r, Math.min(8000, 500*Math.pow(2,i))));
    }
  }
  throw lastErr || new Error("收尾失败");
}


function isInlineable(name){
  const ext=(name.match(/\\.([^.]+)$/)||[])[1]||"";
  return ["png","jpg","jpeg","gif","webp","svg","bmp","ico","pdf","txt","md","json","js","css","xml","csv","html","htm","mp3","wav","flac","ogg","mp4","webm","mov"].includes(ext.toLowerCase());
}

/* ---------- 视图切换(列表 / 图标 / 平铺 / 缩略图 + 大小) ---------- */
const VIEW_KEY="lfs.view", ZOOM_KEY="lfs.zoom";
const VIEW_MODES=["list","icons","tiles","thumbs"];
function isImageName(n){
  const ext=(String(n).match(/\\.([^.]+)$/)||[])[1]||"";
  return ["png","jpg","jpeg","gif","webp","bmp","ico","avif","svg"].includes(ext.toLowerCase());
}
function isVideoName(n){
  const ext=(String(n).match(/\\.([^.]+)$/)||[])[1]||"";
  return ["mp4","m4v","mov","mkv","webm","avi","wmv","flv","ts","m2ts","mpg","mpeg","3gp","rmvb","rm"].includes(ext.toLowerCase());
}
/** 有封面可看(缩略图/视频封面)的条目。 */
function hasCover(n){ return isImageName(n) || isVideoName(n); }
function applyView(){
  document.body.classList.remove("view-list","view-icons","view-tiles","view-thumbs");
  document.body.classList.add("view-"+viewMode);
  for(const b of document.querySelectorAll("#viewSwitch button")){
    b.classList.toggle("on", b.dataset.view===viewMode);
  }
  // 网格尺寸:单元格最小宽度由滑块决定;缩略图模式再放大一档,更接近“大图预览”
  const px = viewMode==="thumbs" ? Math.round(cellSize*1.35) : cellSize;
  document.documentElement.style.setProperty("--cell", px+"px");
  $("zoomLabel").textContent = cellSize+" px";
  $("zoomRange").value = String(cellSize);
  $("zoomBox").style.display = viewMode==="list" ? "none" : "";
}
function setView(v){
  if(!VIEW_MODES.includes(v)) return;
  viewMode=v;
  try{ localStorage.setItem(VIEW_KEY, v); }catch(e){}
  applyView();
}
function setZoom(px){
  cellSize=Math.min(280, Math.max(96, Number(px)||132));
  try{ localStorage.setItem(ZOOM_KEY, String(cellSize)); }catch(e){}
  applyView();
}
function initView(){
  try{
    const v=localStorage.getItem(VIEW_KEY);
    if(VIEW_MODES.includes(v)) viewMode=v;
    const z=Number(localStorage.getItem(ZOOM_KEY));
    if(z>=96 && z<=280) cellSize=z;
  }catch(e){}
  for(const b of document.querySelectorAll("#viewSwitch button")){
    b.addEventListener("click",()=>setView(b.dataset.view));
  }
  $("zoomRange").addEventListener("input",()=>setZoom($("zoomRange").value));
  applyView();
}

/* ---------- 大图预览(lightbox):点缩略图放大,点空白处返回,不跳转链接 ---------- */
let lbList=[], lbIndex=-1;
// 当前预览的缩放倍率与平移量(被 closeLightbox / showLightbox / 滚轮处理共用),
// 必须在使用它们的函数之前声明。
let lbZoom=1, lbPanX=0, lbPanY=0;
function lbImagesInDir(){
  // 当前目录里"可预览"的条目(图片 + 视频),用于左右切换
  return lastEntries.filter(e=>!e.isDir && hasCover(e.name))
    .map(e=>({ name:e.name, rel: cur ? cur+"/"+e.name : e.name, video: isVideoName(e.name) }));
}
function openLightbox(rel, name){
  lbList = lbImagesInDir();
  if(!lbList.length) lbList=[{name:name, rel:rel}];
  lbIndex = Math.max(0, lbList.findIndex(x=>x.rel===rel));
  showLightbox();
  $("lightbox").classList.add("open");
  document.body.style.overflow="hidden";
}
function closeLightbox(){
  $("lightbox").classList.remove("open");
  document.body.style.overflow="";
  // 正在播放的视频要显式暂停,否则移除元素后可能仍在后台解码/占用网络
  const v = $("lbStage").querySelector("video");
  if(v){ try{ v.pause(); v.removeAttribute("src"); v.load(); }catch(e){} }
  $("lbStage").textContent="";
  lbList=[]; lbIndex=-1;
  lbZoom=1; lbPanX=0; lbPanY=0;   // 复位缩放,下一张图从 100% 开始
}
/* ---------- 预览用的内存缓存 ---------- */
// 浏览器缓存可能因隐私设置/隧道代理而失效;这里在同一页面会话内再兜一层:
// 已经取过的原图直接用 blob URL,重复打开预览时零网络请求。
const rawCache = new Map();   // rel -> blob URL
const RAW_CACHE_MAX = 12;     // 最多留 12 张,避免占太多内存

/** 预取原图到内存缓存(大图预览用);失败不抛,交给 <img> 自己回退。 */
function prefetchRaw(rel){
  if(rawCache.has(rel)) return Promise.resolve(rawCache.get(rel));
  return fetch("/raw"+qs(rel)+"&inline=1")
    .then((r) => { if(!r.ok) throw new Error("HTTP "+r.status); return r.blob(); })
    .then((b) => {
      const u = URL.createObjectURL(b);
      rawCache.set(rel, u);
      // 超出上限时释放最早的一个,防止长期浏览把内存吃满
      if(rawCache.size > RAW_CACHE_MAX){
        const k = rawCache.keys().next().value;
        try{ URL.revokeObjectURL(rawCache.get(k)); }catch(e){}
        rawCache.delete(k);
      }
      return u;
    });
}

function showLightbox(){
  const it=lbList[lbIndex];
  if(!it) return;
  const stage=$("lbStage");
  stage.textContent="";

  // ---------- 视频:用播放器而不是图片缩放的交互 ----------
  if(it.video){
    const src = "/raw"+qs(it.rel)+"&inline=1";
    const v = document.createElement("video");
    v.className = "lb-video";
    v.src = src;
    v.controls = true;
    v.autoplay = true;
    v.preload = "metadata";
    v.playsInline = true;
    v.addEventListener("click",(ev)=>ev.stopPropagation());   // 点视频不关闭
    stage.appendChild(v);
    // 视频没有"低清先出"的概念,直接给个说明并清掉提示
    const note=$("lbNote");
    if(note){ note.textContent=""; note.className="lb-note"; }
    $("lbName").textContent = it.name;
    $("lbIdx").textContent = lbList.length>1 ? ((lbIndex+1)+" / "+lbList.length) : "";
    $("lbOpen").href = src;
    $("lbDown").href = "/download"+qs(it.rel);
    const hasPrev=lbList.length>1, hasNext=lbList.length>1;
    $("lbPrev").disabled=!hasPrev; $("lbNext").disabled=!hasNext;
    $("lbPrev").style.display = hasPrev ? "" : "none";
    $("lbNext").style.display = hasNext ? "" : "none";
    resetZoom(null);
    return;
  }

  const spin=document.createElement("div"); spin.className="lb-spin"; spin.textContent="加载中…";
  stage.appendChild(spin);

  // 命中内存缓存就直接用 blob(不再走网络);否则用原来的 URL 并顺手预取
  const cached = rawCache.get(it.rel);
  const fullSrc = cached || ("/raw"+qs(it.rel)+"&inline=1");
  if(!cached) prefetchRaw(it.rel).catch(()=>{});
  const thumbSrc="/thumb"+qs(it.rel);

  // 缩放容器:low 与 hi 都放在它里面,尺寸由 hi 决定,low 绝对定位铺满同一区域。
  // 所有缩放/平移都作用于容器,这样两张图始终对齐、切换时不跳动。
  const zoom=document.createElement("div");
  zoom.className="lb-zoom idle";
  const hi=document.createElement("img");
  hi.className="lb-hi"; hi.alt=it.name; hi.decoding="async";
  const low=document.createElement("img");
  low.className="lb-low"; low.alt=""; low.decoding="async";
  // 点图片本身不关闭预览(点四周空白才关闭,由 stage 的 click 处理)
  hi.addEventListener("click",(ev)=>ev.stopPropagation());
  low.addEventListener("click",(ev)=>ev.stopPropagation());
  zoom.append(hi,low);
  stage.appendChild(zoom);

  let hiLoaded=false, lowShown=false, hiReady=false;
  const note=$("lbNote");
  const setNote=(txt,cls)=>{ if(!note) return; note.textContent=txt||""; note.className="lb-note"+(cls?" "+cls:""); };

  setNote("正在加载低清预览图…","warn");

  low.addEventListener("load",()=>{
    lowShown=true;
    low.classList.add("loaded");
    // 低清先到:若高清还没尺寸信息,就用低清的比例给容器定尺寸,避免图片塌成 0 高
    if(!hiReady && hi.naturalWidth && hi.naturalHeight){ /* 已有 */ }
    if(!hiReady) sizeZoomBy(zoom, low.naturalWidth, low.naturalHeight);
    spin.remove();
    if(!hiLoaded) setNote("正在显示低清预览图(画面可能有压缩),高清原图加载中…","warn");
  });
  low.addEventListener("error",()=>{
    low.remove();
    if(!hiLoaded) setNote("正在加载原图…","warn");
  });

  hi.addEventListener("load",()=>{
    hiLoaded=true; hiReady=true;
    spin.remove();
    // 高清就位:按高清的真实像素尺寸重算容器尺寸(这正是"放大到原始清晰度"的关键),
    // 低清图淡出移除。
    sizeZoomBy(zoom, hi.naturalWidth, hi.naturalHeight);
    resetZoom(zoom);
    if(lowShown){
      low.classList.add("fade");
      setTimeout(()=>low.remove(), 260);
    }
    setNote("");
  });
  hi.addEventListener("error",()=>{
    if(!lowShown){ spin.textContent="图片加载失败"; }
    setNote(lowShown ? "高清原图加载失败,当前为低清预览图(画面可能有压缩)" : "图片加载失败",
            lowShown ? "warn" : "err");
  });

  low.src=thumbSrc;
  hi.src=fullSrc;

  $("lbName").textContent=it.name;
  $("lbIdx").textContent = lbList.length>1 ? ((lbIndex+1)+" / "+lbList.length) : "";
  $("lbOpen").href=fullSrc;
  $("lbDown").href="/download"+qs(it.rel);
  const hasPrev=lbList.length>1, hasNext=lbList.length>1;
  $("lbPrev").disabled=!hasPrev; $("lbNext").disabled=!hasNext;
  $("lbPrev").style.display = hasPrev ? "" : "none";
  $("lbNext").style.display = hasNext ? "" : "none";
  resetZoom(zoom);   // 每张新图从 100% 居中开始(同时清掉上一张的 transform)
}

/* ---------- 预览缩放:滚轮缩放 + 拖动平移 ---------- */

/** 按图片真实像素与可视区分辨率,给容器定一个“刚好铺满可视区”的显示尺寸。 */
function sizeZoomBy(zoom, nw, nh){
  if(!nw || !nh) return;
  const stage=$("lbStage");
  const cs=getComputedStyle(stage);
  const availW=stage.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
  const availH=stage.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
  if(availW<=0 || availH<=0) return;
  // 等比缩放到可视区内(不放大超过原始像素)
  const scale=Math.min(availW/nw, availH/nh, 1);
  const w=Math.max(1, Math.round(nw*scale));
  const h=Math.max(1, Math.round(nh*scale));
  zoom.style.width=w+"px";
  zoom.style.height=h+"px";
  zoom.dataset.baseW=String(w);
  zoom.dataset.baseH=String(h);
}
/** 应用当前的缩放与平移,并刷新百分比显示。 */
function applyZoom(){
  const zoom=$("lbStage").querySelector(".lb-zoom");
  if(!zoom) return;
  // 注意:此处位于 PAGE_HTML 模板字面量内,反引号必须转义,否则会提前结束外层模板。
  zoom.style.transform = "translate("+lbPanX+"px, "+lbPanY+"px) scale("+lbZoom+")";
  const el=$("lbZoomLvl");
  if(el) el.textContent = Math.round(lbZoom*100)+"%";
  zoom.classList.toggle("idle", lbZoom<=1.001);
  zoom.classList.toggle("dragging", lbZoom>1.001);
}
/** 重置为 100% 居中。 */
function resetZoom(zoom){
  lbZoom=1; lbPanX=0; lbPanY=0;
  if(zoom) zoom.style.transform="";
  applyZoom();
}
/** 以某个锚点(默认容器中心)缩放,保证缩放时光标下的内容不跑掉。 */
function zoomAt(zoom, factor, cx, cy){
  const next=Math.min(12, Math.max(0.2, lbZoom*factor));
  if(Math.abs(next-lbZoom)<0.0001) return;
  const rect=zoom.getBoundingClientRect();
  const ax=cx===undefined ? rect.left+rect.width/2 : cx;
  const ay=cy===undefined ? rect.top+rect.height/2 : cy;
  const cxr=ax-(rect.left+rect.width/2);
  const cyr=ay-(rect.top+rect.height/2);
  const k=next/lbZoom;
  lbPanX = cxr - k*(cxr-lbPanX);
  lbPanY = cyr - k*(cyr-lbPanY);
  lbZoom=next;
  applyZoom();
}
function lbStep(d){
  if(lbList.length<2) return;
  lbIndex=(lbIndex+d+lbList.length)%lbList.length;
  showLightbox();
}
function initLightbox(){
  const stage=$("lbStage");

  // 点空白(舞台本身)返回;点图片或容器内部不关闭
  stage.addEventListener("click",(e)=>{ if(e.target===stage) closeLightbox(); });
  $("lbClose").addEventListener("click",closeLightbox);
  $("lbClose2").addEventListener("click",closeLightbox);
  $("lbPrev").addEventListener("click",(ev)=>{ ev.stopPropagation(); lbStep(-1); });
  $("lbNext").addEventListener("click",(ev)=>{ ev.stopPropagation(); lbStep(1); });

  // ---- 滚轮缩放(以光标位置为锚点,缩放时视觉焦点不跑) ----
  stage.addEventListener("wheel",(e)=>{
    if(!$("lightbox").classList.contains("open")) return;
    const zoom=stage.querySelector(".lb-zoom");
    if(!zoom) return;
    e.preventDefault();
    // 触控板/滚轮:向上滚放大,向下滚缩小;按住 Ctrl 时精度更高(浏览器会放大约 1/3)
    const step = e.ctrlKey ? 1.08 : 1.18;
    zoomAt(zoom, e.deltaY < 0 ? step : 1/step, e.clientX, e.clientY);
  }, { passive:false });

  // ---- 放大后可拖动平移 ----
  let dragging=false, sx=0, sy=0, px=0, py=0;
  stage.addEventListener("mousedown",(e)=>{
    const zoom=stage.querySelector(".lb-zoom");
    if(!zoom || lbZoom<=1.001) return;
    if(e.button!==0) return;
    dragging=true; sx=e.clientX; sy=e.clientY; px=lbPanX; py=lbPanY;
    zoom.classList.add("dragging");
    e.preventDefault();
  });
  window.addEventListener("mousemove",(e)=>{
    if(!dragging) return;
    lbPanX=px+(e.clientX-sx);
    lbPanY=py+(e.clientY-sy);
    applyZoom();
  });
  window.addEventListener("mouseup",()=>{
    if(!dragging) return;
    dragging=false;
    const zoom=stage.querySelector(".lb-zoom");
    if(zoom) zoom.classList.remove("dragging");
  });

  // ---- 缩放按钮 ----
  $("lbZoomIn").addEventListener("click",(ev)=>{ ev.stopPropagation(); const z=stage.querySelector(".lb-zoom"); if(z) zoomAt(z,1.25); });
  $("lbZoomOut").addEventListener("click",(ev)=>{ ev.stopPropagation(); const z=stage.querySelector(".lb-zoom"); if(z) zoomAt(z,1/1.25); });
  $("lbZoomReset").addEventListener("click",(ev)=>{
    ev.stopPropagation(); const z=stage.querySelector(".lb-zoom");
    if(z) resetZoom(z);
  });

  // ---- 双击切换 100% / 适应窗口 ----
  stage.addEventListener("dblclick",(e)=>{
    const z=stage.querySelector(".lb-zoom");
    if(!z) return;
    e.preventDefault();
    if(lbZoom>1.001) resetZoom(z);
    else zoomAt(z, 2, e.clientX, e.clientY);
  });

  document.addEventListener("keydown",(e)=>{
    if(!$("lightbox").classList.contains("open")) return;
    const z=stage.querySelector(".lb-zoom");
    if(e.key==="Escape"){ e.preventDefault(); closeLightbox(); }
    else if(e.key==="ArrowLeft"){ e.preventDefault(); lbStep(-1); }
    else if(e.key==="ArrowRight"){ e.preventDefault(); lbStep(1); }
    else if((e.key==="+"||e.key==="=") && z){ e.preventDefault(); zoomAt(z,1.25); }
    else if((e.key==="-"||e.key==="_") && z){ e.preventDefault(); zoomAt(z,1/1.25); }
    else if(e.key==="0" && z){ e.preventDefault(); resetZoom(z); }
  });
}

/* ---------- 单独分享(仅主端口/本机可用) ---------- */
// CAN_SHARE / IS_MAIN 已在页面脚本开头声明(必须在 render 之前),此处不再重复

function fmtAgo(ts){
  if(!ts) return "";
  const d=Math.floor((Date.now()-ts)/1000);
  if(d<60) return "刚刚";
  if(d<3600) return Math.floor(d/60)+" 分钟前";
  if(d<86400) return Math.floor(d/3600)+" 小时前";
  return Math.floor(d/86400)+" 天前";
}
function copyText(t,btn){
  const done=()=>{ if(btn){ const o=btn.textContent; btn.textContent="已复制"; setTimeout(()=>btn.textContent=o,1200);} };
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(done).catch(()=>{ fallbackCopy(t); done(); });
  } else { fallbackCopy(t); done(); }
}
function fallbackCopy(t){
  const ta=document.createElement("textarea"); ta.value=t; ta.style.position="fixed"; ta.style.opacity="0";
  document.body.appendChild(ta); ta.select();
  try{ document.execCommand("copy"); }catch(e){}
  ta.remove();
}
function sharePathOf(sh){ return sh.external ? (sh.absRoot || '(本机文件夹)') : ("/" + sh.rel); }

async function loadShares(){
  if(!CAN_SHARE) return;
  try{
    const r = await fetch("/api/share/list");
    const j = await r.json();
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    sharesCache = j.shares || [];
    renderShares();
  }catch(e){
    $("shareList").innerHTML = '<div class="empty-hint">无法读取分享列表: '+escName(e.message)+'</div>';
  }
}
/** 当前目录是否落在某个已分享的子树内(用于禁用该行的分享按钮)。 */
function sharingAt(pathRel){
  const p = pathRel || "";
  return sharesCache.find(s=> s.rel===p || (p && s.rel.startsWith(p+"/")));
}
/** 该路径是否位于已分享范围内(含自己),或本身就是某个已分享目录的祖先。 */
function isSharedOrInside(pathRel){
  const p = pathRel || "";
  return sharesCache.some(s=> s.rel===p || (p && s.rel.startsWith(p+"/")) || (p && p.startsWith(s.rel+"/")));
}
function renderShares(){
  const box=$("shareList"), cnt=$("shareCnt");
  if(cnt){ cnt.textContent=sharesCache.length; cnt.style.display = sharesCache.length? "" : "none"; }
  if(!sharesCache.length){
    box.innerHTML = '<div class="empty-hint">还没有单独分享的文件夹。在下面列表里点某个文件夹右侧的「分享」即可把它单独开一个端口。</div>';
    return;
  }
  box.textContent="";
  for(const sh of sharesCache){
    const item=document.createElement("div"); item.className="sh-item";
    const info=document.createElement("div"); info.className="info";
    const nm=document.createElement("div"); nm.className="nm";
    nm.textContent="📁 "+sh.name;
    if(sh.external){
      const ex=document.createElement("span"); ex.className="tag"; ex.style.marginLeft="6px";
      ex.textContent="本机外部"; ex.title="该分享指向共享根之外的目录";
      nm.appendChild(ex);
    }
    const meta=document.createElement("div"); meta.className="meta";
    meta.append(document.createTextNode("端口 "+sh.port+" · 路径 "+sharePathOf(sh)+" · "));
    // 口令状态:区分「读写 + 只读」双口令 / 仅只读 / 无需口令
    const tagLock=document.createElement("span");
    if(sh.hasRw && sh.hasRo){
      tagLock.className="tag lock"; tagLock.textContent="🔐 读写+只读口令";
    } else if(sh.hasRo){
      tagLock.className="tag lock"; tagLock.textContent="👁 仅只读口令";
    } else if(sh.hasRw){
      tagLock.className="tag lock"; tagLock.textContent="🔒 需要口令";
    } else {
      tagLock.className="tag free"; tagLock.textContent="🔓 无需口令";
    }
    meta.appendChild(tagLock);
    meta.append(document.createTextNode(" · 创建于 "+fmtAgo(sh.createdAt)));
    info.append(nm,meta);
    const urls=document.createElement("div"); urls.className="urls";
    for(const u of (sh.urls||[])){
      const row=document.createElement("div"); row.className="sh-url";
      const code=document.createElement("code"); code.textContent=u;
      const b=document.createElement("button"); b.className="btn-sm"; b.type="button"; b.textContent="复制";
      b.addEventListener("click",()=>copyText(u,b));
      const o=document.createElement("a"); o.className="btn-sm"; o.href=u; o.target="_blank"; o.rel="noopener"; o.textContent="打开";
      row.append(code,b,o); urls.appendChild(row);
    }
    info.appendChild(urls);
    const ops=document.createElement("div"); ops.className="ops";
    const bPort=document.createElement("button"); bPort.className="btn-sm"; bPort.type="button"; bPort.textContent="改端口";
    bPort.addEventListener("click",()=>changeSharePort(sh));
    const bPwd=document.createElement("button"); bPwd.className="btn-sm"; bPwd.type="button";
    bPwd.textContent = sh.hasRw? "改读写口令":"设读写口令";
    bPwd.addEventListener("click",()=>setSharePwd(sh));
    const bRoPwd=document.createElement("button"); bRoPwd.className="btn-sm"; bRoPwd.type="button";
    bRoPwd.textContent = sh.hasRo? "改只读口令":"设只读口令";
    bRoPwd.title="只读口令只能浏览与下载,不能上传/删除/重命名";
    bRoPwd.addEventListener("click",()=>setShareRoPwd(sh));
    const bStop=document.createElement("button"); bStop.className="btn-sm"; bStop.type="button"; bStop.textContent="取消分享";
    bStop.style.color="#dc2626"; bStop.style.borderColor="#fecaca";
    bStop.addEventListener("click",()=>stopShare(sh));
    ops.append(bPort,bPwd,bRoPwd,bStop);
    item.append(info,ops);
    box.appendChild(item);
  }
}

/**
 * 打开分享对话框。
 * pathRel 有值 → 分享共享根内的这个子文件夹(原有用法);
 * pathRel 为空且 absMode 为真 → 分享本机任意文件夹(管理员指定绝对路径)。
 */
function openShareDialog(pathRel, name, absMode){
  if(!CAN_SHARE){ msg("当前页面不是主共享页面,不能创建单独分享", true); return; }
  const external = !!absMode || !pathRel;
  $("shareModal").dataset.external = external ? "1" : "";
  $("shareModal").dataset.path = pathRel || "";
  $("smTitle").textContent = external ? '分享本机文件夹' : ('分享文件夹「'+name+'」');
  $("smPath").textContent = external ? '(共享根之外的本机目录)' : ("/"+pathRel);
  $("smAbsWrap").style.display = external ? "" : "none";
  $("smAbs").value = "";
  $("smPort").value = "";
  $("smUsePwd").checked = false;
  $("smPwdWrap").style.display = "none";
  $("smPwd").value = "";
  $("smUseRoPwd").checked = false;
  $("smRoPwdWrap").style.display = "none";
  $("smRoPwd").value = "";
  $("smMsg").textContent = ""; $("smMsg").className = "msg";
  $("smOk").disabled = false;
  $("shareModal").classList.add("open");
}
function closeModal(id){ $(id).classList.remove("open"); }

/** 调服务端弹 Windows 原生文件夹选择框(仅本机可用)。 */
async function pickLocalFolder(){
  const btn = $("smBrowse");
  const m = $("smMsg");
  if(btn){ btn.disabled = true; }
  m.textContent = "已弹出系统选择框,请在本机屏幕上选择文件夹…"; m.className = "msg";
  try{
    const r = await fetch("/api/share/pick-folder", { method:"POST" });
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error || ("HTTP "+r.status));
    if(j.cancelled){ m.textContent = "已取消选择"; m.className = "msg"; return; }
    $("smAbs").value = j.path || "";
    m.textContent = "已选择:" + (j.path || ""); m.className = "msg ok";
  }catch(e){
    m.textContent = "无法弹出系统选择框("+e.message+"),请手动填写完整路径"; m.className = "msg err";
  }finally{
    if(btn){ btn.disabled = false; }
  }
}

async function submitShare(){
  const external = $("shareModal").dataset.external === "1";
  const pathRel = $("shareModal").dataset.path || "";
  const absPath = external ? $("smAbs").value.trim() : "";
  const portRaw = $("smPort").value.trim();
  const usePwd = $("smUsePwd").checked;
  const pwd = usePwd ? $("smPwd").value : "";
  const useRo = $("smUseRoPwd").checked;
  const roPwd = useRo ? $("smRoPwd").value : "";
  const m=$("smMsg");

  if(external && !absPath){
    m.textContent = "请先选择或填写要分享的文件夹路径"; m.className="msg err"; return;
  }
  if(portRaw){
    const n=Number(portRaw);
    if(!Number.isInteger(n) || n<1024 || n>65535){ m.textContent="端口需在 1024-65535 之间"; m.className="msg err"; return; }
  }
  if(pwd && roPwd && pwd === roPwd){
    m.textContent="读写口令与只读口令不能相同"; m.className="msg err"; return;
  }
  // 分享共享根之外的文件夹,风险明显更高,再确认一次(避免手滑把敏感目录开出去)
  if(external){
    const pwdNote = (pwd || roPwd) ? "已设置口令。" : "⚠ 未设口令,任何能访问该端口的设备都可直接读写。";
    // 注意:这里位于 PAGE_HTML 模板字面量内,字符串里的换行转义要写双反斜杠,
    // 否则会被外层模板解析成真实换行而把字符串截断(本项目已踩过几次)。
    const ok = confirm(
      "即将把本机文件夹单独开一个端口对外共享:\\n\\n" + absPath + "\\n\\n" +
      "该文件夹及其所有子目录的内容都会被访问者看到(可读,未设只读口令时还可写)。\\n" + pwdNote +
      "\\n\\n确定要继续吗?"
    );
    if(!ok) return;
  }
  $("smOk").disabled=true;
  m.textContent="正在创建…"; m.className="msg";
  try{
    const body = external
      ? { absPath, port: portRaw?Number(portRaw):0, password: pwd||"", roPassword: roPwd||"" }
      : { path: pathRel, port: portRaw?Number(portRaw):0, password: pwd||"", roPassword: roPwd||"" };
    const r = await fetch("/api/share/create", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify(body)});
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    closeModal("shareModal");
    showShareAddress(j.share);
    await loadShares();
  }catch(e){
    m.textContent = e.message; m.className="msg err";
    $("smOk").disabled=false;
  }
}
function showShareAddress(sh){
  $("amTitle").textContent = '「'+sh.name+'」已开始单独分享';
  $("amPath").textContent = "共享路径: /"+sh.rel+"    端口: "+sh.port;
  const box=$("amUrls"); box.textContent="";
  for(const u of (sh.urls||[])){
    const row=document.createElement("div"); row.className="sh-url";
    const code=document.createElement("code"); code.textContent=u;
    const b=document.createElement("button"); b.className="btn-sm"; b.type="button"; b.textContent="复制";
    b.addEventListener("click",()=>copyText(u,b));
    row.append(code,b); box.appendChild(row);
  }
  // 说明口令情况:让分享者清楚该把哪个口令给谁
  if(sh.hasRw && sh.hasRo){
    $("amNote").textContent = "已设置两个口令 —— 读写口令可用于上传/删除/重命名;只读口令只能浏览和下载。把对应的口令给对应的人即可。";
  } else if(sh.hasRo){
    $("amNote").textContent = "只设置了只读口令 —— 用它访问的人只能浏览和下载,不能修改内容。若要允许某些人写入,可在面板里再设一个读写口令。";
  } else if(sh.hasRw){
    $("amNote").textContent = "已设置读写口令:别人打开地址时浏览器会要求输入口令,输入后即可读写。";
  } else {
    $("amNote").textContent = "未设口令:任何能访问该地址的设备都可直接读写。可在「单独分享」面板里随时加口令或取消分享。";
  }
  $("addrModal").classList.add("open");
}
async function stopShare(sh){
  if(!confirm('确定取消分享「'+sh.name+'」吗？\\n端口 '+sh.port+' 上的访问会立即失效(共享的文件本身不会被删除)。')) return;
  try{
    const r = await fetch("/api/share/remove", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({id:sh.id})});
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    msg("已取消分享:「"+sh.name+"」");
    await loadShares();
  }catch(e){ msg("取消分享失败: "+e.message, true); }
}
async function setSharePwd(sh){
  const wantPwd = sh.hasRw
    ? confirm('「'+sh.name+'」当前已设读写口令。\\n\\n点“确定”修改口令,点“取消”则取消口令。')
    : true;
  let pwd = "";
  if(wantPwd){
    pwd = prompt('请为「'+sh.name+'」设置读写口令(留空表示不设):', "");
    if(pwd === null) return;
  }
  try{
    const r = await fetch("/api/share/password", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({id:sh.id, password: pwd||""})});
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    msg(pwd? "已更新读写口令" : "已取消读写口令");
    await loadShares();
  }catch(e){ msg("修改口令失败: "+e.message, true); }
}

async function setShareRoPwd(sh){
  const wantPwd = sh.hasRo
    ? confirm('「'+sh.name+'」当前已设只读口令。\\n\\n点“确定”修改,点“取消”则取消只读口令(有读写口令时不影响读写)。')
    : true;
  let pwd = "";
  if(wantPwd){
    pwd = prompt('请为「'+sh.name+'」设置只读口令(留空表示不设):\\n用此口令访问的人只能浏览和下载,不能上传/删除/重命名。', "");
    if(pwd === null) return;
  }
  try{
    const r = await fetch("/api/share/ropassword", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({id:sh.id, roPassword: pwd||""})});
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    msg(pwd? "已设置只读口令" : "已取消只读口令");
    await loadShares();
  }catch(e){ msg("修改只读口令失败: "+e.message, true); }
}

/** 修改某个分享的端口(端到端:先停旧监听再起新监听,失败会自动回滚)。 */
async function changeSharePort(sh){
  const input = prompt('为「'+sh.name+'」指定新的访问端口(1024-65535):', String(sh.port));
  if(input === null) return;                       // 取消
  const n = Number(String(input).trim());
  if(!Number.isInteger(n) || n<1024 || n>65535){ msg("端口需在 1024-65535 之间", true); return; }
  if(n === sh.port){ msg("端口未改变"); return; }
  try{
    const r = await fetch("/api/share/port", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({id:sh.id, port:n})});
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    msg("已改用端口 "+j.share.port);
    await loadShares();
  }catch(e){ msg("改端口失败: "+e.message, true); await loadShares(); }
}

/* ---------- 操作日志(仅主端口可见) ---------- */
async function loadLogs(){
  try{
    const r = await fetch("/api/log/recent");
    const j = await r.json();
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    $("logSub").textContent = "级别: "+j.level+" · 共 "+j.logs.length+" 条";
    const box=$("logList"); box.textContent="";
    if(!j.logs.length){ box.innerHTML='<div class="log-row"><span class="d">暂无日志</span></div>'; return; }
    for(const L of j.logs){
      const row=document.createElement("div"); row.className="log-row"+(L.ok?"":" bad");
      const d=new Date(L.ts), p=(x)=>String(x).padStart(2,"0");
      const t=document.createElement("span"); t.className="t";
      t.textContent = p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds());
      const a=document.createElement("span"); a.className="a"; a.textContent=L.actionLabel + (L.ok?"":" ✗");
      const w=document.createElement("span"); w.className="w";
      w.textContent = (L.host && L.host!==L.ip) ? L.ip+"("+L.host+")" : L.ip;
      const det=document.createElement("span"); det.className="d";
      const parts=[];
      if(L.device) parts.push(L.device);
      if(L.where) parts.push(L.where);
      if(L.path) parts.push("/"+L.path);
      if(L.detail) parts.push(L.detail);
      det.textContent = parts.join(" · ");
      row.append(t,a,w,det); box.appendChild(row);
    }
  }catch(e){
    $("logList").innerHTML = '<div class="log-row"><span class="d">无法读取日志: '+escName(e.message)+'</span></div>';
  }
}

/* ---------- 根目录访问密码(仅主端口/本机可设置) ---------- */
async function loadPwdState(){
  try{
    const r = await fetch("/api/rootpwd");
    const j = await r.json();
    if(!r.ok) throw new Error(j.error||("HTTP "+r.status));
    renderPwdState(!!j.enabled);
  }catch(e){
    const box=$("pwdState");
    box.textContent = "无法读取密码状态: "+e.message;
    box.style.color = "#dc2626";
  }
}
function renderPwdState(on){
  const box=$("pwdState");
  box.textContent = on
    ? "✅ 已启用:局域网设备打开本页会先要求输入密码(本机访问免输)。"
    : "⚪ 未启用:任何能访问本机端口的设备都可浏览、下载、上传、删除。";
  box.style.color = on ? "#15803d" : "";
}
function pwdMsg(text, bad){
  const el=$("pwdMsg");
  el.textContent = text || "";
  el.style.color = bad ? "#dc2626" : "#15803d";
}
async function submitPwd(clear){
  const a=$("pwdNew").value, b=$("pwdNew2").value;
  if(clear){
    if(!confirm("确定取消密码保护吗?取消后局域网内任何设备都能直接读写共享目录。")) return;
  }else{
    if(!a){ pwdMsg("请先输入新密码(留空表示不修改)", true); return; }
    if(a!==b){ pwdMsg("两次输入的密码不一致", true); return; }
  }
  const btn = clear ? $("pwdClear") : $("pwdSave");
  btn.disabled = true;
  pwdMsg(clear ? "正在取消…" : "正在保存…", false);
  try{
    const r = await fetch("/api/rootpwd", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ password: clear ? "" : a })
    });
    const j = await r.json().catch(()=>({}));
    if(!r.ok || !j.ok) throw new Error(j.error||("HTTP "+r.status));
    $("pwdNew").value=""; $("pwdNew2").value="";
    renderPwdState(!!j.enabled);
    pwdMsg(j.enabled ? "密码已保存,局域网访问立即生效" : "已取消密码保护(局域网恢复免密访问)", false);
  }catch(e){
    pwdMsg("操作失败: "+e.message, true);
  }finally{
    btn.disabled = false;
  }
}
function initPwdUi(){
  if(!CAN_SHARE) return;                       // 单独分享端口:不显示管理入口
  $("btnPwdPanel").addEventListener("click", async ()=>{
    const p=$("pwdPanel");
    p.style.display = p.style.display==="none" ? "" : "none";
    if(p.style.display!=="none") await loadPwdState();
  });
  $("pwdSave").addEventListener("click", ()=>submitPwd(false));
  $("pwdClear").addEventListener("click", ()=>submitPwd(true));
  $("pwdNew2").addEventListener("keydown", (e)=>{ if(e.key==="Enter") submitPwd(false); });
}

function initShareUi(){
  if(!CAN_SHARE) return;                       // 单独分享端口:不显示管理入口
  $("hdrActions").style.display = "";
  $("btnSharePanel").addEventListener("click", async ()=>{
    const p=$("sharePanel");
    p.classList.toggle("open");
    if(p.classList.contains("open")) await loadShares();
  });
  $("btnLog").addEventListener("click", async ()=>{
    const p=$("logPanel");
    p.style.display = p.style.display==="none" ? "" : "none";
    if(p.style.display!=="none") await loadLogs();
  });
  $("smCancel").addEventListener("click", ()=>closeModal("shareModal"));
  $("smOk").addEventListener("click", submitShare);
  $("smBrowse").addEventListener("click", pickLocalFolder);
  $("btnPickFolder").addEventListener("click", ()=>openShareDialog("", "", true));
  $("smUsePwd").addEventListener("change", ()=>{ $("smPwdWrap").style.display = $("smUsePwd").checked? "":"none"; });
  $("smUseRoPwd").addEventListener("change", ()=>{ $("smRoPwdWrap").style.display = $("smUseRoPwd").checked? "":"none"; });
  $("amClose").addEventListener("click", ()=>closeModal("addrModal"));
  $("shareModal").addEventListener("click", (e)=>{ if(e.target===$("shareModal")) closeModal("shareModal"); });
  $("addrModal").addEventListener("click", (e)=>{ if(e.target===$("addrModal")) closeModal("addrModal"); });
  document.addEventListener("keydown",(e)=>{ if(e.key==="Escape"){ closeModal("shareModal"); closeModal("addrModal"); } });
  loadShares();
}

/** 只读访问:隐藏上传区并显示提示条(服务端也会拒绝一切写操作)。 */
/**
 * 只读访问:隐藏上传区(这是权限控制,必须保留)。
 * 写操作入口既然已经不可见、服务端也会拒绝写请求,页面上就不再额外显示解释性横幅。
 */
function initReadonly(){
  if(!READONLY) return;
  const drop=$("drop");
  if(drop) drop.style.display="none";
  const nb=$("newBar");
  if(nb) nb.style.display="none";   // 只读访问不显示「新建文件夹」
}

/** 批量下载:绑定全选 / 清空 / 下载按钮;以及新建文件夹。 */
function initBulkDownload(){
  $("selAll").addEventListener("click",()=>pickAll(true));
  $("selNone").addEventListener("click",()=>pickAll(false));
  $("selZip").addEventListener("click",downloadPicked);
  $("btnNewFolder").addEventListener("click",newFolder);
  const head=$("selAllHead");
  if(head) head.addEventListener("change",()=>pickAll(head.checked));
  syncSelBar();
}

load();
connectLive();
initView();
initLightbox();
initReadonly();
initBulkDownload();
initShareUi();
initPwdUi();
</script>
</body>
</html>`;

/* ---------------- 本机判定 ---------------- */

/**
 * 判断请求是否来自「本机网页端」。按需求,本机无论用回环地址还是自己的网卡 IP 访问都算本机。
 * 判定依据是 TCP 对端地址,客户端无法伪造(不像 X-Forwarded-For 之类请求头)。
 * 为避免 DNS 重绑定/代理绕过,这里只认回环与「本机自己的 IP」两类。
 */
const localIPs = new Set(['127.0.0.1', '::1']);
function refreshLocalIPs() {
  localIPs.clear();
  localIPs.add('127.0.0.1');
  localIPs.add('::1');
  for (const list of Object.values(os.networkInterfaces())) {
    for (const it of list || []) {
      if (it.address) localIPs.add(it.family === 'IPv6' && it.address.includes('%')
        ? it.address.split('%')[0] : it.address);
    }
  }
}

function isLocalRequest(req) {
  const raw = (req.socket && req.socket.remoteAddress) || '';
  let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (ip === '::1') ip = '127.0.0.1';
  if (localIPs.has(ip) || localIPs.has(raw)) return true;
  // 回环网段 127.0.0.0/8 一律视为本机
  if (/^127\./.test(ip)) return true;
  return false;
}

/* ---------------- 分享管理接口(仅本机) ---------------- */

/** 读取请求体(限长,防滥用),返回解析后的 JSON(允许为空)。 */
function readJsonBody(req, limit = 16 * 1024) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { req.destroy(); resolve({}); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const s = Buffer.concat(chunks).toString('utf8').trim();
      if (!s) return resolve({});
      try { resolve(JSON.parse(s)); } catch { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}

/** 拒绝非本机请求(分享管理是主机专属能力)。 */
function requireLocal(ctx, req, res, action, detail) {
  if (isLocalRequest(req)) return true;
  logAction({ action: 'deny', ctx, req, ok: false, status: 403, detail: detail || '分享管理仅限本机' });
  sendJson(res, 403, { ok: false, error: '仅本机网页端可以进行分享管理(请在本机浏览器操作)' });
  return false;
}

/**
 * 分享管理只存在于主端口:单独分享端口上即使是本机也一律拒绝,
 * 这样“不能在共享文件夹下再创建共享”是在服务端强制的,不依赖前端隐藏按钮。
 */
function isMainScope(ctx) { return !!ctx && ctx.kind === 'main'; }

async function handleShareApi(ctx, req, res, url) {
  const p = url.pathname;

  // 分享管理/日志只在主端口存在;单独分享端口上一律 404,顺带避免暴露主机能力
  if (!isMainScope(ctx)) {
    logAction({ action: 'deny', ctx, req, ok: false, status: 404, detail: '单独分享端口不提供分享管理' });
    throw new HttpError(404, '接口不存在');
  }

  if (req.method === 'GET' && p === '/api/share/list') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    return sendJson(res, 200, {
      ok: true,
      isLocal: true,
      sharePortBase: SHARE_PORT_BASE,
      shares: [...shares.values()].map(shareInfo),
    });
  }

  // 弹出 Windows 原生的文件夹选择框(仅本机;无桌面会话时会失败,前端降级为手填)
  if (req.method === 'POST' && p === '/api/share/pick-folder') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    return handlePickFolder(ctx, req, res);
  }

  if (req.method === 'POST' && p === '/api/share/create') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    let sh;
    try {
      sh = await createShare({
        rel: body.path,
        // 外部文件夹分享:管理员在网页端指定的本机绝对路径(与 path 二选一)
        absPath: typeof body.absPath === 'string' && body.absPath.trim() ? body.absPath.trim() : '',
        port: body.port,
        password: typeof body.password === 'string' && body.password ? body.password : '',
        roPassword: typeof body.roPassword === 'string' && body.roPassword ? body.roPassword : '',
        webdav: !!body.webdav,
      });
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      logAction({ action: 'shareAdd', ctx, req, path: body.absPath || body.path, ok: false, status, detail: `创建失败:${e.message}` });
      return sendJson(res, status, { ok: false, error: e.message });
    }
    const pwdDesc = [sh.pwdHash ? '读写口令' : '', sh.roHash ? '只读口令' : ''].filter(Boolean).join('+');
    logAction({
      action: 'shareAdd', ctx, req, path: sh.external ? sh.absRoot : sh.rel, ok: true,
      detail: `端口 ${sh.port}${sh.external ? '、本机外部文件夹' : ''}${pwdDesc ? '、已设' + pwdDesc : '、无口令'}${sh.webdav ? '、WebDAV 已启用' : ''}`,
    });
    return sendJson(res, 200, { ok: true, share: shareInfo(sh) });
  }

  if (req.method === 'POST' && p === '/api/share/remove') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    try {
      const sh = await removeShare(String(body.id || ''));
      logAction({ action: 'shareDel', ctx, req, path: sh.rel, ok: true, detail: `释放端口 ${sh.port}` });
      return sendJson(res, 200, { ok: true, removed: sh.id });
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      logAction({ action: 'shareDel', ctx, req, ok: false, status, detail: e.message });
      return sendJson(res, status, { ok: false, error: e.message });
    }
  }

  // 口令设置:/api/share/password 设读写口令;/api/share/ropassword 设只读口令
  if (req.method === 'POST' && p === '/api/share/password') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    const sh = shares.get(String(body.id || ''));
    if (!sh) return sendJson(res, 404, { ok: false, error: '该分享不存在或已取消' });
    const pw = typeof body.password === 'string' ? body.password : '';
    // 读写口令与只读口令不能相同,否则无法区分权限
    if (pw && sh.roHash && verifyPwd(pw, sh.roHash)) {
      return sendJson(res, 400, { ok: false, error: '读写口令不能与只读口令相同' });
    }
    setSharePwd(sh, pw);
    logAction({
      action: 'sharePwd', ctx, req, path: sh.rel, ok: true,
      detail: pw ? '已设置读写口令' : '已取消读写口令',
    });
    return sendJson(res, 200, { ok: true, share: shareInfo(sh) });
  }

  if (req.method === 'POST' && p === '/api/share/ropassword') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    const sh = shares.get(String(body.id || ''));
    if (!sh) return sendJson(res, 404, { ok: false, error: '该分享不存在或已取消' });
    const pw = typeof body.roPassword === 'string' ? body.roPassword : '';
    if (pw && sh.pwdHash && verifyPwd(pw, sh.pwdHash)) {
      return sendJson(res, 400, { ok: false, error: '只读口令不能与读写口令相同' });
    }
    setShareRoPwd(sh, pw);
    logAction({
      action: 'sharePwd', ctx, req, path: sh.rel, ok: true,
      detail: pw ? '已设置只读口令' : '已取消只读口令',
    });
    return sendJson(res, 200, { ok: true, share: shareInfo(sh) });
  }

  // 开关 WebDAV(Windows 可将该分享映射为网络位置)
  if (req.method === 'POST' && p === '/api/share/webdav') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    const sh = shares.get(String(body.id || ''));
    if (!sh) return sendJson(res, 404, { ok: false, error: '该分享不存在或已取消' });
    try {
      await setShareWebdav(sh, !!body.enabled);
      logAction({
        action: 'shareWebdav', ctx, req, path: sh.rel, ok: true,
        detail: body.enabled ? '已启用 WebDAV' : '已关闭 WebDAV',
      });
      return sendJson(res, 200, { ok: true, share: shareInfo(sh) });
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      logAction({ action: 'shareWebdav', ctx, req, path: sh.rel, ok: false, status, detail: e.message });
      return sendJson(res, status, { ok: false, error: e.message });
    }
  }

  if (req.method === 'POST' && p === '/api/share/port') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    const sh = shares.get(String(body.id || ''));
    if (!sh) return sendJson(res, 404, { ok: false, error: '该分享不存在或已取消' });
    try {
      const updated = await setSharePort(sh, body.port);
      logAction({ action: 'sharePort', ctx, req, path: sh.rel, ok: true, detail: `端口改为 ${updated.port}` });
      return sendJson(res, 200, { ok: true, share: shareInfo(updated) });
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      logAction({ action: 'sharePort', ctx, req, path: sh.rel, ok: false, status, detail: e.message });
      return sendJson(res, status, { ok: false, error: e.message });
    }
  }

  if (req.method === 'GET' && p === '/api/log/recent') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    return sendJson(res, 200, { ok: true, level: LOG_LEVEL, logs: recentLogs.slice(-120).reverse() });
  }

  // 根目录访问密码:查看状态 / 设置或取消。只有本机能改(局域网设备既看不到入口也调不动接口)
  if (req.method === 'GET' && p === '/api/rootpwd') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    return sendJson(res, 200, { ok: true, enabled: !!rootPwdHash });
  }
  if (req.method === 'POST' && p === '/api/rootpwd') {
    if (!requireLocal(ctx, req, res, 'deny')) return;
    const body = await readJsonBody(req);
    const pw = typeof body.password === 'string' ? body.password : '';
    try {
      setRootPwd(pw);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      logAction({ action: 'rootPwd', ctx, req, ok: false, status, detail: e.message });
      return sendJson(res, status, { ok: false, error: e.message });
    }
    logAction({
      action: 'rootPwd', ctx, req, ok: true,
      detail: pw ? '已设置根目录访问密码(局域网访问需输入)' : '已取消根目录访问密码',
    });
    return sendJson(res, 200, { ok: true, enabled: !!rootPwdHash });
  }

  throw new HttpError(404, '接口不存在');
}

/* ---------------- 路由 ---------------- */

async function handleRequest(ctx, req, res) {
  const url = new URL(req.url, 'https://x');
  const p = url.pathname;
  const started = Date.now();

  // 主端口「根目录访问密码」:只拦局域网来的请求,本机(回环与本机网卡 IP)免输
  if (ctx.kind === 'main' && rootPwdHash && !isLocalRequest(req)) {
    const role = challengeAccess(req, res, ctx, verifyRootPwd, '根目录访问密码错误或未提供');
    if (!role) return;
    ctx.role = role.level;
    ctx.viaRootPwd = true;   // 供日志区分“本机直连”与“局域网凭密码进入”
  }

  // 单独分享端口的口令校验(未设口令则直接放行)
  if (ctx.kind === 'share') {
    const sh = shares.get(ctx.shareId);
    // 分享可能已被取消(或服务重启后记录失效):此时连接不应继续可用
    if (!sh) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end('该分享已取消');
    }
    if (sh.pwdHash || sh.roHash) {
      const role = challengeAccess(req, res, ctx, (pwd) => verifyPwdRole(sh, pwd));
      if (!role) return;
      // 命中只读口令:整个请求期间 ctx.role='ro',下面会拦掉所有写操作
      ctx.role = role.level;
      ctx.viaRoPwd = role.level === 'ro';
    } else {
      ctx.role = 'rw';   // 未设任何口令
    }
  }

  try {
    // 只读口令进来的请求:除“浏览/下载/预览/实时同步”外一律拒绝。
    // 放在最前面统一拦截,避免遗漏某个写接口。
    if (ctx.role === 'ro' && isWriteRequest(req.method, p)) {
      logAction({ action: 'deny', ctx, req, path: url.searchParams.get('path') || url.searchParams.get('dir') || '',
                  ok: false, status: 403, detail: '只读口令,禁止写操作' });
      return sendJson(res, 403, {
        ok: false, error: '当前为只读访问(你使用的是只读口令),不能修改任何内容',
        readonly: true,
      });
    }

    if (req.method === 'GET' && p === '/') {
      logAction({ action: 'browse', ctx, req, path: '', ok: true });
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(renderPage(ctx));
    }
    if (req.method === 'GET' && p === '/api/list') {
      const data = await listDir(ctx, url.searchParams.get('path') || '');
      logAction({ action: 'browse', ctx, req, path: data.publish, ok: true });
      return sendJson(res, 200, data);
    }
    // 实时同步通道:服务器推送共享目录变更,浏览器收到后静默刷新当前目录
    // 批量打包下载:先 prepare 落盘(可查进度),再 get 按 Range 下载(支持断点续传)
    if (req.method === 'POST' && p === '/api/download-zip/prepare') {
      return await handleZipPrepare(ctx, req, res, url);
    }
    if (req.method === 'GET' && p === '/api/download-zip/status') {
      return handleZipStatus(ctx, req, res, url);
    }
    if ((req.method === 'GET' || req.method === 'HEAD') && p === '/api/download-zip/get') {
      return await handleZipGet(ctx, req, res, url);
    }
    if (req.method === 'GET' && p === '/api/events') {
      return handleEvents(ctx, req, res);
    }
    // 分享管理 / 日志查看 / 根目录访问密码:仅本机网页端
    if (p.startsWith('/api/share/') || p === '/api/log/recent' || p === '/api/rootpwd') {
      return await handleShareApi(ctx, req, res, url);
    }
    if ((req.method === 'GET' || req.method === 'HEAD') && (p === '/download' || p === '/raw')) {
      const rel = url.searchParams.get('path') || '';
      const { abs } = await resolveExisting(ctx, rel);
      const st = await fsp.stat(abs);
      if (st.isDirectory()) throw new HttpError(400, '请先进入目录,不支持下载整个文件夹(可逐文件下载)');
      logAction({
        action: p === '/raw' ? 'preview' : 'download', ctx, req, path: rel, ok: true,
        detail: fmtSize(st.size),
      });
      return serveFile(req, res, abs, st);
    }
    if (req.method === 'POST' && p === '/api/upload') {
      return await handleUpload(ctx, req, res, url);
    }
    // 大文件分片上传:按需查询进度 → 逐片上传 → 收尾落盘
    if (req.method === 'GET' && p === '/api/upload/status') {
      return await handleUploadStatus(ctx, req, res, url);
    }
    if (req.method === 'POST' && p === '/api/upload/chunk') {
      return await handleUploadChunk(ctx, req, res, url);
    }
    if (req.method === 'POST' && p === '/api/upload/finish') {
      return await handleUploadFinish(ctx, req, res, url);
    }
    // 低清预览图(装了 sharp 才有;未装会返回 503,前端自动回退到原图)
    if ((req.method === 'GET' || req.method === 'HEAD') && p === '/thumb') {
      return await serveThumb(ctx, req, res, url);
    }
    if (req.method === 'POST' && p === '/api/delete') {
      return await handleDelete(ctx, req, res, url);
    }
    if (req.method === 'POST' && p === '/api/rename') {
      return await handleRename(ctx, req, res, url);
    }
    if (req.method === 'POST' && p === '/api/mkdir') {
      return await handleMkdir(ctx, req, res, url);
    }
    throw new HttpError(404, '接口不存在');
  } catch (err) {
    const ms = Date.now() - started;
    if (err && err.code === 'ENOENT') {
      logAction({ action: 'deny', ctx, req, path: url.searchParams.get('path') || '', ok: false, status: 404, detail: `不存在(${ms}ms)` });
      return sendJson(res, 404, { ok: false, error: '文件或目录不存在' });
    }
    if (err && err.code === 'EACCES') {
      logAction({ action: 'deny', ctx, req, path: url.searchParams.get('path') || '', ok: false, status: 403, detail: '没有访问权限' });
      return sendJson(res, 403, { ok: false, error: '没有访问权限' });
    }
    // 4xx 属于“客户端请求不合法/被拒绝”,归为 DENY;5xx 才是服务端异常,归为 ERROR。
    // 这样日志里能一眼区分“有人乱试”与“程序出问题”。
    if (err instanceof HttpError) {
      const act = err.status >= 500 ? 'error' : 'deny';
      logAction({ action: act, ctx, req, path: url.searchParams.get('path') || '', ok: false, status: err.status, detail: err.message });
      return sendJson(res, err.status, { ok: false, error: err.message });
    }
    logAction({ action: 'error', ctx, req, path: url.searchParams.get('path') || '', ok: false, status: 500, detail: err && err.message });
    // 未预期异常:打印完整堆栈便于排查(用红色前缀与常规日志区分)
    console.error(paint('  [STACK] ', C.bold + C.brightRed) + (err && err.stack ? err.stack : String(err)));
    if (!res.headersSent) sendJson(res, 500, { ok: false, error: '服务器内部错误' });
    else res.destroy();
  }
}

/* ---------------- 启动 ---------------- */

/**
 * 双栈监听:先尝试绑定 IPv6 通配地址 '::' —— 内核会把 IPv4-mapped 连接一并交给它,
 * 于是同一端口同时接受 IPv6 与 IPv4 连接;系统没有启用 IPv6 时自动退回
 * '0.0.0.0'(仅 IPv4),保证服务总能起来。
 * onReady(dualStack) 在任一次绑定成功后调用;onFatal 收到的是真正的监听错误(如端口占用)。
 */
const IPV6_UNAVAILABLE_CODES = new Set(['EAFNOSUPPORT', 'EPROTONOSUPPORT', 'EADDRNOTAVAIL', 'EINVAL', 'ENOTSUP']);

function listenDual(server, port, onReady, onFatal) {
  // onFatal 没传时兜底:打印错误并退出,避免“端口占用”变成难懂的 TypeError
  const fatal = typeof onFatal === 'function' ? onFatal : (e) => {
    errorLine(e && e.message ? e.message : String(e));
    process.exit(1);
  };
  let fellBack = false;
  server.on('error', (e) => {
    if (!fellBack && e && IPV6_UNAVAILABLE_CODES.has(e.code)) {
      fellBack = true;                    // IPv6 不可用:退回仅 IPv4,不让服务起不来
      server.listen(port, '0.0.0.0');
      return;
    }
    fatal(e);
  });
  server.once('listening', () => {
    const addr = server.address();
    onReady(!!(addr && addr.family === 'IPv6'));
  });
  server.listen({ port, host: '::', ipv6Only: false });
}

/** 本机 IPv6 协议栈是否可用(有 IPv6 回环地址即可认为可用)。 */
function ipv6Available() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const it of list || []) if (it && it.family === 'IPv6' && it.internal) return true;
  }
  return false;
}

/** fe80::/10 是链路本地地址。 */
function isLinkLocalV6(addr) {
  const a = String(addr).toLowerCase();
  return a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb');
}

/**
 * 列出本机可用于局域网访问的地址,IPv4 与 IPv6 分开:
 *   - v4:形如 "192.168.1.5"
 *   - v6:可直接拼进 URL 的 "[2001:db8:abcd:1234:5a6b:7c8d:9e0f:1a2b]" 形式
 *   - v6LinkLocal:链路本地地址(fe80::/10)的个数。这类地址必须带上网卡作用域 ID
 *     (%以太网 / %15)才能访问,直接给出 URL 反而点不开,所以只报个数。
 * 另外跳过 Teredo(2001:0::/32):那是 NAT 穿透隧道地址,不能当局域网地址使用。
 */
function lanAddrs() {
  const v4 = [];
  const v6 = [];
  let v6LinkLocal = 0;
  for (const list of Object.values(os.networkInterfaces())) {
    for (const it of list || []) {
      if (!it || it.internal) continue;
      if (it.family === 'IPv4') { v4.push(it.address); continue; }
      if (it.family !== 'IPv6') continue;
      const addr = String(it.address).split('%')[0];   // 去掉 %scopeid
      if (isLinkLocalV6(addr)) { v6LinkLocal++; continue; }
      if (/^2001:0:/i.test(addr)) continue;            // Teredo 隧道地址
      v6.push(`[${addr}]`);
    }
  }
  const uniq = (a) => [...new Set(a)].sort();
  return { v4: uniq(v4), v6: uniq(v6), v6LinkLocal };
}

/**
 * 递归清理共享目录下上次异常退出残留的 `.uploading-*` 临时文件。
 * 这些文件名均以 `.uploading-<pid>-<ts>` 结尾;正常上传会自动改名删除,
 * 出现残留只可能是进程在 写入→改名 之间被杀,可安全删。
 */
/**
 * 递归清理共享目录下“已无意义”的上传临时文件。
 *
 * 注意:分片上传的临时文件 `<目标>.uploading-chunk` 及其 `.json` 元数据**必须保留**,
 * 它们是断点续传的依据(注释里承诺了“进程重启后依然可续传”);只有同时缺少元数据
 * 的孤儿分片才清理。旧版单片上传残留的 `.uploading-<pid>-<ts>` 则可安全删除。
 */
const CHUNK_PART_SUFFIX = '.uploading-chunk';
function cleanupUploadingTemps() {
  const walk = (dir) => {
    let names;
    try { names = fs.readdirSync(dir); } catch { return; }
    const set = new Set(names);
    for (const n of names) {
      const p = path.join(dir, n);
      let st;
      try { st = fs.lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) continue; // 不进符号链接
      if (st.isDirectory()) { walk(p); continue; }

      // 分片续传的文件:保留本体与元数据;只有孤立的分片(元数据已丢失)才清掉
      if (n.endsWith(CHUNK_PART_SUFFIX)) {
        if (!set.has(n + '.json')) { try { fs.rmSync(p); } catch {} }
        continue;
      }
      if (n.endsWith(CHUNK_PART_SUFFIX + '.json')) {
        const partName = n.slice(0, -'.json'.length);
        if (!set.has(partName)) { try { fs.rmSync(p); } catch {} }  // 孤立的元数据
        continue;
      }
      // 旧版单片上传残留:进程被杀后留下的半截文件,可安全删
      if (n.includes('.uploading-')) { try { fs.rmSync(p); } catch {} }
    }
  };
  try { walk(SHARE_ROOT); } catch { /* 忽略 */ }
}

function main() {
  if (!fs.existsSync(SHARE_ROOT)) {
    errorLine(`共享目录不存在: ${SHARE_ROOT}`);
    errorLine(`请修改 ${CONFIG_PATH} 中的 "shareRoot" 指向真实文件夹后重试。`);
    process.exit(1);
  }
  // 越界判定基准与监视线程都用共享根的真实路径(shareRoot 自身可能是符号链接/目录联接)
  try {
    SHARE_ROOT_REAL = fs.realpathSync(SHARE_ROOT);
  } catch {
    SHARE_ROOT_REAL = SHARE_ROOT;
  }
  refreshLocalIPs();
  cleanupUploadingTemps();
  loadSharp();   // 尽早报告低清预览是否可用
  const watcher = watchDir();
  if (!watcher) warnLine('当前文件系统不支持递归目录监视,仅本服务自身的写入会实时同步。');
  if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    errorLine(`未找到 HTTPS 证书: ${CERT_FILE}`);
    errorLine('请先运行: node gen-cert.js(需要 openssl,可用 Git Bash 自带)。');
    process.exit(1);
  }

  loadShares();
  loadRootAuth();

  const server = https.createServer(
    { cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) },
    (req, res) => handleRequest(makeCtxMain(), req, res)
  );

  const onListenError = (e) => {
    if (e.code === 'EADDRINUSE') {
      errorLine(`端口 ${PORT} 已被占用。可在 ${CONFIG_PATH} 中修改 "port"。`);
    } else if (e.code === 'EACCES' || e.code === 'EPERM') {
      errorLine(`没有权限监听端口 ${PORT}(<1024 的端口需要管理员权限),可在 ${CONFIG_PATH} 中改用大端口。`);
    } else {
      errorLine(e && e.message ? e.message : String(e));
    }
    process.exit(1);
  };

  // 双栈监听:IPv6 与 IPv4 共用同一个端口(系统未启用 IPv6 时自动退回仅 IPv4)
  listenDual(server, PORT, async (dualStack) => {
    const bar = '═'.repeat(52);
    console.log(paint(bar, C.cyan));
    console.log(paint('  📁 局域网文件共享  ', C.bold + C.brightCyan) + paint('已启动', C.green));
    console.log(paint(bar, C.cyan));
    note('共享目录  ', paint(SHARE_ROOT, C.bold));
    const addrs = lanAddrs();
    const url = (h) => paint(`https://${h}:${PORT}/`, C.bold + C.brightGreen);
    if (addrs.v4.length === 0 && addrs.v6.length === 0) {
      note('访问地址  ', url('localhost'));
    } else {
      note('本机访问  ', url('localhost'));
      for (const ip of addrs.v4) note('局域网访问', url(ip));
      // IPv6 地址一律写成 [地址] 形式,直接粘进浏览器即可
      for (const ip of addrs.v6) note('IPv6 访问 ', url(ip));
    }
    if (addrs.v6LinkLocal) {
      note('IPv6 提示 ', paint(`另有 ${addrs.v6LinkLocal} 个链路本地地址(fe80::/10):需带网卡作用域 ID 才能访问,故未列出`, C.dim));
    }
    note('监听方式  ', dualStack
      ? paint('IPv4 + IPv6 双栈', C.green) + paint('  (IPv6 设备的浏览器可直接访问上面列出的 IPv6 地址)', C.dim)
      : paint('仅 IPv4', C.yellow) + paint('  (系统未启用 IPv6,已退回 IPv4 监听)', C.dim));
    note('访问密码  ', rootPwdHash
      ? paint('已启用', C.green) + paint('  (局域网设备打开网页会要求输入密码;本机免输,可在网页右上角「🔒 访问密码」里改)', C.dim)
      : paint('未启用', C.dim) + paint('  (局域网内任何设备都能直接读写;可在网页右上角「🔒 访问密码」里设置)', C.dim));
    note('证书文件  ', paint(CERT_FILE, C.gray) + paint('  (分发给局域网设备并信任,可消除浏览器警告)', C.dim));
    note('实时同步  ', paint('已开启', C.green) + paint(' —— 共享目录内容变化时,正在浏览的页面会自动静默更新', C.dim));
    note('操作日志  ', paint(LOG_LEVEL, C.bold) + paint('  (可改 config.json 的 logLevel: quiet/normal/verbose)', C.dim));
    note('终端颜色  ', COLOR_ENABLED
      ? paint('已启用', C.green) + paint('  (重定向到文件时自动关闭;可设 NO_COLOR=1 手动关闭)', C.dim)
      : paint('未启用', C.yellow) + paint('  (非终端输出;设 FORCE_COLOR=1 可强制开启)', C.dim));

    // 恢复上次运行期间创建的单独分享(端口被占用时跳过并提示,不影响主服务)
    if (shares.size) await restoreShares();
    else note('单独分享  ', paint('无', C.dim) + paint('  (在主页面点某个文件夹的「分享」即可创建)', C.dim));
    console.log(paint(bar, C.cyan));
    console.log(paint('  按 Ctrl+C 停止', C.dim));
    console.log(paint(bar, C.cyan));
  }, onListenError);
}

/** 启动时恢复 shares.json 里的单独分享;某个端口起不来只跳过该条。 */
async function restoreShares() {
  let restored = 0;
  let skipped = 0;
  for (const sh of [...shares.values()]) {
    let real;
    try {
      if (sh.external) {
        // 外部分享:直接用记录的绝对路径做 realpath 复核(目录可能被删/改名/换盘)
        real = await fsp.realpath(sh.absRoot);
        const st = await fsp.stat(real);
        if (!st.isDirectory()) throw new Error('已不是文件夹');
        // 重启时再挡一次系统关键目录(配置可能被手工改过)
        assertSafeExternalRoot(real);
      } else {
        const ctxMain = makeCtxMain();
        const { abs } = await resolveExisting(ctxMain, sh.rel);   // 目录可能已被删/移动
        const st = await fsp.stat(abs);
        if (!st.isDirectory()) throw new Error('已不是文件夹');
        const clash = findSharingAncestor2(sh.rel, sh.id);
        if (clash) throw new Error(`与「${clash.name}」包含关系冲突`);
        real = abs;
      }
    } catch (e) {
      // 目录本身已不可用(被删除/改名/包含关系冲突):这条分享已经没有意义,移除记录
      errorLine(`单独分享「${sh.name}」(端口 ${sh.port})未能恢复: ${e.message} (已移除该分享记录)`);
      shares.delete(sh.id);
      saveShares();
      continue;
    }

    // 端口只是暂时被占用(比如上一次的进程还没退干净)时,保留配置并稍后重试,
    // 不能因为一次启动失败就丢掉用户设好的分享(含口令)。
    sh.real = real;
    sh.absRoot = real;
    try {
      await listenShare(sh);
      restored++;
    } catch (e) {
      skipped++;
      warnLine(`单独分享「${sh.name}」(端口 ${sh.port})暂时无法监听: ${e.message}`);
      warnLine(`已保留该分享配置,稍后会自动重试(可修改 port 排除占用)。`);
      scheduleShareRetry(sh);
    }
  }
  note('单独分享  ', skipped
    ? paint(`已恢复 ${restored} 个`, C.green) + paint(`,${skipped} 个待重试`, C.yellow)
    : paint(`已恢复 ${restored} 个`, C.green));
}

/**
 * 为「端口暂时被占用」的分享安排重试:每 15 秒试一次,最多 20 次(约 5 分钟)。
 * 期间用户也可以手动在网页里改端口。
 */
const shareRetryTimers = new Map();
function scheduleShareRetry(sh) {
  if (shareRetryTimers.has(sh.id)) return;
  let tries = 0;
  const timer = setInterval(async () => {
    tries++;
    if (!shares.has(sh.id) || shareServers.has(sh.id)) { clearInterval(timer); shareRetryTimers.delete(sh.id); return; }
    try {
      await listenShare(sh);
      clearInterval(timer);
      shareRetryTimers.delete(sh.id);
      note('单独分享  ', paint(`「${sh.name}」`, C.magenta)
        + paint(`(端口 ${sh.port})`, C.dim)
        + paint(' 重试成功,已开始对外服务。', C.green));
      publishChange('up', '');   // 让已打开的页面刷新分享面板
    } catch (e) {
      if (tries >= 20) {
        clearInterval(timer);
        shareRetryTimers.delete(sh.id);
        warnLine(`单独分享「${sh.name}」(端口 ${sh.port})多次重试仍失败: ${e.message}`);
        warnLine(`请在网页「单独分享」面板中改一个端口后重试。`);
      }
    }
  }, 15000);
  timer.unref?.();
  shareRetryTimers.set(sh.id, timer);
}

/** 恢复时检查嵌套冲突(忽略自身)。 */
function findSharingAncestor2(rel, exceptId) {
  for (const sh of shares.values()) {
    if (sh.id === exceptId) continue;
    if (relEq(rel, sh.rel) || relInside(sh.rel, rel) || relInside(rel, sh.rel)) return sh;
  }
  return null;
}

main();
