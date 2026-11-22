// 文件会话源（P1 独立运行 / P2 兜底）：直接读 ~/.dsh/sessions 下的 v4 日志。
// 解析法来自冷库 da145f2a 与 _tools/export-sessions.mjs 的实测打通版本：
// 多帧 zstd 按魔数 28 B5 2F FD 切分逐帧解压；坏帧跳过并如实计数。
// 只读，绝不写会话文件。P2 宿主内优先走官方读取契约（ServiceSessionSource），本源兜底。

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import os from 'node:os';
import crypto from 'node:crypto';

const MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);
const LOG_NAME = 'session.v4.jsonl.zstd';

export function decodeZstdFrames(buf) {
  const starts = [];
  let i = 0;
  while (true) {
    const idx = buf.indexOf(MAGIC, i);
    if (idx < 0) break;
    starts.push(idx);
    i = idx + 4;
  }
  let out = '';
  let ok = 0;
  for (let k = 0; k < starts.length; k++) {
    const s = starts[k];
    const e = k + 1 < starts.length ? starts[k + 1] : buf.length;
    try {
      out += zlib.zstdDecompressSync(buf.subarray(s, e)).toString('utf8');
      ok++;
    } catch {
      // 单帧坏了（含 live 会话未写完的尾帧）跳过，不影响其它帧
    }
  }
  return { text: out, frames: starts.length, ok };
}

export class FileSessionSource {
  constructor(root = path.join(os.homedir(), '.dsh', 'sessions')) {
    this.root = root;
  }

  /** 枚举全部会话日志，返回轻量条目（不解压）。 */
  async list() {
    const entries = [];
    if (!fs.existsSync(this.root)) return entries;
    for (const ws of fs.readdirSync(this.root)) {
      const wp = path.join(this.root, ws);
      let st;
      try { st = fs.statSync(wp); } catch { continue; }
      if (!st.isDirectory()) continue;
      for (const sess of fs.readdirSync(wp)) {
        const file = path.join(wp, sess, LOG_NAME);
        let fst;
        try { fst = fs.statSync(file); } catch { continue; }
        if (!fst.isFile()) continue;
        // 修 B4：内容哈希指纹（对齐官方 sha256），等长改内容＋复原 mtime 也能识别。
        // 代价：list 需读全文件算哈希（增量约 1s 级），换一致性。
        const buf = fs.readFileSync(file);
        const hash = crypto.createHash('sha256').update(buf).digest('hex');
        entries.push({
          dirId: sess,
          wsKey: ws,
          file,
          size: fst.size,
          mtimeMs: Math.floor(fst.mtimeMs),
          fingerprint: `${fst.size}:${Math.floor(fst.mtimeMs)}:${hash}`,
        });
      }
    }
    return entries;
  }

  /** 读一个会话：头、最新标题、事件流。格式版本不符显式报错，不静默误解析。 */
  async read(entry) {
    const raw = fs.readFileSync(entry.file);
    const { text, frames, ok } = decodeZstdFrames(raw);
    const events = [];
    let header = null;
    let title = '';
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let ev;
      try { ev = JSON.parse(line); } catch { continue; }
      if (ev.type === 'session') {
        header = ev;
        continue;
      }
      if (ev.type === 'session/title' || ev.type === 'title') {
        const t = ev.data?.title ?? ev.title;
        if (typeof t === 'string' && t) title = t; // 取最新
        continue;
      }
      events.push(ev);
    }
    if (!header) throw new Error(`no session header: ${entry.file}`);
    if (header.version !== 4) throw new Error(`unsupported session format v${header.version}: ${entry.file}`);
    return {
      header,
      title,
      events,
      partial: ok < frames, // 有坏帧/未写完尾帧 ⇒ 如实标注
      frames,
      okFrames: ok,
      fingerprint: entry.fingerprint,
    };
  }
}