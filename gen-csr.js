'use strict';

/**
 * gen-csr.js —— 给「免费 CA（Let's Encrypt / ZeroSSL / FreeSSL 等）」生成一把新私钥 + CSR
 *
 * 用法:
 *   node gen-csr.js <域名> [额外SAN,逗号分隔]
 *   node gen-csr.js files.example.com
 *   node gen-csr.js files.example.com 192.168.50.251,::1,lan.home
 *   node gen-csr.js files.example.com --force        # 覆盖已存在的同名 key/csr
 *
 * 产出(都在 certs/ 下,不会覆盖你现在能用的 server.key):
 *   certs/<域名>.key   新私钥(2048 位 RSA)
 *   certs/<域名>.csr   CSR,PEM 文本,直接复制粘贴给 CA
 *
 * 重要提醒(内网场景):
 *   - 免费 CA 只会为**你验证过的域名**签发,CSR 里的 IP SAN 通常会被丢掉;
 *   - 所以签完之后,访问必须用**域名**,并且每台设备要把该域名解析到这台机器的内网 IP
 *     (hosts 文件 / 路由器 DNS / 本地 DNS),否则浏览器仍按 IP 校验,依旧报“名称不匹配”;
 *   - 域名指向内网 IP 时,HTTP-01 文件验证走不通,只能用 **DNS-01**(加一条 TXT 记录)。
 *
 * 需要 openssl(建议 ≥ 1.1.1;Windows 可用 Git 自带的
 * C:\Program Files\Git\usr\bin\openssl.exe)。
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const ROOT_DIR = __dirname;
const CERT_DIR = path.join(ROOT_DIR, 'certs');

/** 把一个 SAN 参数规范成 openssl 的写法:能解析成 IP 就当 IP,否则当 DNS。 */
function toSanItem(raw) {
  const v = String(raw).trim();
  if (!v) return '';
  if (/^(ip|dns):/i.test(v)) return v.replace(/^ip:/i, 'IP:').replace(/^dns:/i, 'DNS:');
  return net.isIP(v) ? `IP:${v}` : `DNS:${v}`;
}

/** 极简域名校验,避免把明显写错的参数喂给 openssl。 */
function assertDomain(d) {
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(d)) {
    console.error(`[ERROR] 域名格式看起来不对: ${d}`);
    console.error('        应该是形如 files.example.com 的完整域名(不要带 https:// 或路径)。');
    process.exit(1);
  }
}

function main() {
  const argv = process.argv.slice(2).filter((a) => a !== '--force');
  const force = process.argv.includes('--force');
  const domain = String(argv[0] || '').trim().toLowerCase();

  if (!domain) {
    console.error('用法: node gen-csr.js <域名> [额外SAN,逗号分隔] [--force]');
    console.error('例如: node gen-csr.js files.example.com 192.168.50.251,::1');
    process.exit(1);
  }
  assertDomain(domain);

  const extras = String(argv[1] || '').split(',').map(toSanItem).filter(Boolean);
  // CN 与第一个 SAN 都是域名;额外 SAN 里若和域名重复就去重
  const san = [`DNS:${domain}`];
  for (const e of extras) if (!san.includes(e)) san.push(e);

  const keyFile = path.join(CERT_DIR, `${domain}.key`);
  const csrFile = path.join(CERT_DIR, `${domain}.csr`);
  for (const f of [keyFile, csrFile]) {
    if (fs.existsSync(f) && !force) {
      console.error(`[ERROR] 已存在: ${f}`);
      console.error('        要重新生成请加 --force(会覆盖这把新私钥/CSR,不影响 certs/server.key)。');
      process.exit(1);
    }
  }
  fs.mkdirSync(CERT_DIR, { recursive: true });

  const args = [
    'req', '-new', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-keyout', keyFile, '-out', csrFile,
    '-subj', `/CN=${domain}`,
    '-addext', `subjectAltName=${san.join(',')}`,
  ];

  console.log('正在生成私钥 + CSR …');
  console.log('  CN  =', domain);
  console.log('  SAN =', san.join(', '));
  try {
    execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    if (e && e.stderr) console.error(String(e.stderr));
    console.error('');
    console.error('[ERROR] 生成失败。常见原因:');
    console.error('  1) 找不到 openssl —— 装一下,或 Windows 上把 Git 自带的加进 PATH:');
    console.error('     $env:PATH = "C:\\Program Files\\Git\\usr\\bin;$env:PATH"');
    console.error('  2) openssl 版本太老(不支持 -addext),需要 >= 1.1.1');
    process.exit(1);
  }

  const csr = fs.readFileSync(csrFile, 'utf8').trim();
  console.log('');
  console.log('完成 ✔');
  console.log('  私钥:', keyFile, '  ← 留在本机,绝不要发给 CA 或别人');
  console.log('  CSR :', csrFile);
  console.log('');
  console.log('把下面整段(含 -----BEGIN/END----- 两行)粘贴到 CA 的“CSR”输入框:');
  console.log('------------------------------------------------------------');
  console.log(csr);
  console.log('------------------------------------------------------------');
  console.log('');
  console.log('拿到签好的证书之后:');
  console.log('  1) 把 CA 返回的证书(通常叫 certificate.crt / domain.crt)内容存成 certs/server.crt');
  console.log('     —— 若 CA 还给了中间证书(chain),把它接在 server.crt 后面一起保存;');
  console.log(`  2) 用新私钥:要么把 ${path.basename(keyFile)} 改名成 server.key,`);
  console.log('     要么改 config.json 的 "keyFile" 指向它;');
  console.log('  3) 重启服务(node server.js / start.bat);');
  console.log('  4) 各设备用域名访问,并确保该域名解析到这台机器的内网 IP。');
}

main();
