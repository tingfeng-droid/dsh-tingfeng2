// 增量同步：枚举 → 指纹比对 → 只重读变化的会话 → 整会话重建索引。
// 源无关：P1 用 FileSessionSource，P2 宿主内用 ServiceSessionSource（官方读取契约）。

import { buildDocs } from './extract.js';

/**
 * @param {object} store RecallStore
 * @param {object} source {list(), read(entry)}
 * @param {object} opts {onProgress, batchSize}
 */
export async function sync(store, source, opts = {}) {
  const t0 = Date.now();
  const entries = await source.list();
  const known = store.fingerprints();
  const seen = new Set();
  let added = 0, updated = 0, skipped = 0, failed = 0, partial = 0;
  const failures = [];

  for (const entry of entries) {
    // 指纹预检（只 stat，不解压）：dirId 即会话 id 是宿主命名约定；
    // 若历史上 header.id 与 dirId 不一致，此处必不命中，会走读取路径，正确性不受影响。
    if (known.get(entry.dirId) === entry.fingerprint) {
      seen.add(entry.dirId);
      skipped++;
      continue;
    }
    let data;
    try {
      data = await source.read(entry);
    } catch (e) {
      failed++;
      failures.push({ file: entry.file, error: String(e?.message ?? e) });
      continue;
    }
    const id = data.header.id ?? entry.dirId;
    seen.add(id);
    const fp = data.fingerprint ?? entry.fingerprint;
    if (known.get(id) === fp) { skipped++; continue; }
    const docs = buildDocs(data.events);
    // 修 B13：标题入检索语料（标题独占内容可达）；null 标题（读不出）不建文档
    if (typeof data.title === 'string' && data.title) {
      docs.push({ seq: -1, type: 'session/title', time: data.header.createdAt ?? 0, text: data.title });
    }
    store.replaceSession({
      sessionId: id,
      cwd: data.header.cwd ?? '',
      createdAt: data.header.createdAt ?? 0,
      parentSession: data.header.parentSession ?? '',
      delegationDepth: data.header.delegationDepth ?? 0,
      title: data.title ?? null,
      fingerprint: fp,
      eventCount: data.events.length,
      partial: data.partial,
    }, docs);
    if (known.has(id)) updated++; else added++;
    if (data.partial) partial++;
    if (opts.onProgress && (added + updated) % (opts.batchSize ?? 20) === 0) {
      opts.onProgress({ added, updated, skipped, failed, done: seen.size, total: entries.length });
    }
  }

  let removed = 0;
  for (const id of known.keys()) {
    if (!seen.has(id)) { store.removeSession(id); removed++; }
  }

  const elapsedMs = Date.now() - t0;
  store.setMeta('lastSyncAt', Date.now());
  store.setMeta('totalSessions', entries.length);
  store.setMeta('lastSyncMs', elapsedMs);
  store.setMeta('partialSessions', partial);
  return { added, updated, removed, skipped, failed, partial, total: entries.length, elapsedMs, failures };
}