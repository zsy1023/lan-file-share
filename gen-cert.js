'use strict';

/**
 * gen-cert.js —— 用系统 openssl 生成自签名证书(含本机局域网 IP 的 SAN)
 *
 * 用法: node gen-cert.js [额外IP ...]
 * 需要 openssl 在 PATH 中(Windows 上 Git Bash / Win64 OpenSSL 自带)。
 * 证书有效期 397 天,到期后重新运行本脚本即可。
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT_DIR = __dirname;
const CONFIG = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'config.json'), 'utf8'));
const CERT_FILE = path.resolve(ROOT_DIR, CONFIG.certFile || 'certs/server.crt');
const KEY_FILE = path.resolve(ROOT_DIR, CONFIG.keyFile || 'certs/server.key');

function lanIPs() {
  const out = new Set(['127.0.0.1']);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const it of list || []) {
      if (it.family === 'IPv4' && !it.internal) out.add(it.address);
    }
  }
  return [...out];
}

function main() {
  const ips = [...new Set([...lanIPs(), ...process.argv.slice(2)])];
  if (!ips.length) {
    console.error('未检测到网卡 IP,请通过命令行参数手动传入,如: node gen-cert.js 192.168.1.10');
    process.exit(1);
  }

  const cn = ips.find((ip) => ip !== '127.0.0.1') || ips[0];
  const san = ['DNS:localhost', ...ips.map((ip) => `IP:${ip}`)].join(',');

  fs.mkdirSync(path.dirname(CERT_FILE), { recursive: true });

  const args = [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-keyout', KEY_FILE, '-out', CERT_FILE,
    '-days', '397',
    '-subj', `/CN=${cn}`,
    '-addext', `subjectAltName=${san}`,
  ];

  console.log('正在生成自签名证书…');
  console.log('  SAN =', san);
  try {
    const out = execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    console.log(out ? out.toString() : '');
  } catch (e) {
    if (e && e.stderr) console.error(e.stderr.toString());
    console.error('生成失败。请确认 openssl 可用:运行  openssl version');
    console.error('Windows 用户可安装 Git for Windows 或 https://slproweb.com/products/Win32OpenSSL.html');
    process.exit(1);
  }

  console.log('完成 ✔');
  console.log('  证书文件 : ' + CERT_FILE);
  console.log('  私钥文件 : ' + KEY_FILE);
  console.log('');
  console.log('浏览器访问 https 会提示“证书不受信任”,这是自签名证书的正常现象。');
  console.log('要让局域网设备彻底消除警告,把证书文件导入各设备的“受信任的根证书”,见 README.md。');
}

main();
