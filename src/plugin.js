// dsh-tingfeng2 — DSH 宿主插件入口（仅宿主侧，无前端半边）。
// 旁路持久索引 + 中文双字滑窗召回 + 子串兜底。官方包零改动：
// 只消费 ctx.sessionQuery 的读取契约（listSessions/readSession/readTitleSnapshots），
// 搜索、排序、翻页、索引全在本包自己的 SQLite 里，官方后端演进互不干涉。
//
// 四个只读工具：recall_search / recall_read / recall_list / recall_restore。
// 隐私四件套：标题私密标记整段排除、标题读不出失败关闭、不可信数据随机 token 边界、拒止式凭据打码。
// recall_restore：无台账回源还原——索引只存占位符，原值不落地映射；须 confirmUnmasked=true 显式授权
// 才经宿主 readSession 回源读原事件文本；私密标题/读不出/子代理/会话头或事件缺失一律失败关闭。

import path from 'node:path';
import os from 'node:os';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { RecallStore } from './store.js';
import { FileSessionSource } from './source-file.js';
import { ServiceSessionSource } from './source-service.js';
import { sync } from './sync.js';
import { search } from './search.js';
import { publish, redact, redactDeep, isPrivateTitle } from './privacy.js';
import { normalizeForRedact } from './tokenize.js';
import { extractEventText } from './extract.js';

export const name = 'recall';
export const inject = ['tools', 'sessionQuery'];

const OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: { content: { type: 'string', required: true } },
  },
  render: (_args, value) => [{ type: 'text', text: String(value?.content ?? '') }],
};

const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 50;
const MAX_CHARS = 12000;

function currentSessionId(exec) {
  const id = exec?.agent?.session?.header?.id;
  return typeof id === 'string' && id ? id : undefined;
}

function clampInt(v, def, max) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), max) : def;
}

function fmtTime(ms) {
  if (!ms) return '未知时间';
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 16);
}

function coverageNote(store) {
  const indexed = store.counts().sessions;
  const total = Number(store.getMeta('totalSessions') ?? 0);
  const at = Number(store.getMeta('lastSyncAt') ?? 0);
  const err = store.getMeta('lastSyncError');
  const parts = [`索引覆盖 ${indexed}/${total} 个会话`];
  if (at) parts.push(`最近同步 ${fmtTime(at)}`);
  if (indexed < total) parts.push('索引尚未建全，结果可能不完整');
  if (err) parts.push(`最近同步出错：${err}`);
  return parts.join('，');
}

function renderSearch(res, query) {
  const lines = [];
  if (!res.hits.length) {
    lines.push(`没有命中「${query}」的历史会话。可换个更短的关键词、用 op=OR 放宽多词，或先用 recall_list 看有哪些会话。`);
  } else {
    lines.push(`命中「${query}」的会话 ${res.total} 个${res.fallbackUsed ? '（全文未中，已用原文子串兜底）' : ''}：`);
    for (const h of res.hits) {
      lines.push('', `## ${h.title || '(无标题)'}  [${h.sessionId}]`);
      lines.push(`工作目录 ${h.cwd} · 创建 ${fmtTime(h.createdAt)} · 命中 ${h.matchCount} 处`);
      for (const s of h.snippets) lines.push(`- (seq ${s.seq} · ${s.type} · ${fmtTime(s.time)}) ${s.text}`);
    }
    if (res.nextOffset != null) lines.push('', `还有更多：用 offset=${res.nextOffset} 翻下一页。`);
  }
  const cov = res.coverage;
  const covParts = [`索引覆盖 ${cov.indexedSessions}/${cov.totalSessions} 个会话`];
  if (cov.lastSyncAt) covParts.push(`最近同步 ${fmtTime(cov.lastSyncAt)}`);
  if (cov.indexedSessions < cov.totalSessions) covParts.push('索引尚未建全，结果可能不完整');
  if (cov.lastSyncError) covParts.push(`最近同步出错：${cov.lastSyncError}`);
  lines.push('', covParts.join('，'));
  let body = lines.join('\n');
  if (body.length > MAX_CHARS) body = body.slice(0, MAX_CHARS) + '\n…（输出超长已截断，可用 offset 翻页或减小 limit）';
  return body;
}

export function apply(ctx, config = {}) {
  const dbPath = config.dbPath ?? path.join(os.homedir(), '.dsh', 'recall', 'index.sqlite');
  const intervalMs = clampInt(config.syncIntervalMs, 60000, 3600000);
  const store = new RecallStore(dbPath);
  const source = new ServiceSessionSource(ctx, new FileSessionSource());

  let syncing = false;
  let disposed = false;
  let currentSync = Promise.resolve();
  async function runSync() {
    if (syncing || disposed) return;
    syncing = true;
    currentSync = (async () => {
      try {
        await sync(store, source);
        if (!disposed) { try { store.setMeta('lastSyncError', ''); } catch { /* 库可能已关 */ } }
      } catch (e) {
        if (!disposed) { try { store.setMeta('lastSyncError', String(e?.message ?? e).slice(0, 200)); } catch { /* 同上 */ } }
      } finally {
        syncing = false;
      }
    })();
    return currentSync;
  }
  runSync();
  const timer = setInterval(runSync, intervalMs);
  timer.unref?.();
  ctx.on('dispose', () => {
    disposed = true;
    clearInterval(timer);
    // 修 B2/R2-1：排空在途 sync 再关库，但设 5s 上界——sync 挂起时不无限拖住句柄。
    let timeoutHandle;
    let drained = false;
    const drain = Promise.resolve(currentSync).then(() => { drained = true; }).catch(() => { drained = true; });
    const timeout = new Promise((resolve) => {
      timeoutHandle = setTimeout(resolve, 5000);
      timeoutHandle.unref?.();
    });
    Promise.race([drain, timeout]).then(() => {
      clearTimeout(timeoutHandle);
      // O3：超时强制关库可观测——在途 sync 未完成时关库前记一条 meta，便于排查（不再静默吞错）。
      if (!drained) { try { store.setMeta('lastSyncError', 'dispose 超时（5s）强制关库，在途同步可能未完成'); } catch { /* 库可能已关 */ } }
      try { store.close(); } catch { /* 已关 */ }
    });
  });

  ctx.tools.register(defineTool({
    name: 'recall_search',
    description:
      '在历史会话里按关键词检索（默认跨全部工作目录，中文按字面召回，英文亦可），返回命中会话与原文片段。' +
      '已知文件名、函数名、报错文本、某个决定或专有名词时用它直接定位记忆；命中后用 recall_read 读完整上下文。' +
      '多个关键词默认 AND，可设 op=OR；单字中文自动走原文子串兜底。',
    parameters: {
      query: { type: 'string', required: true, description: '关键词或短语，多个用空格分隔。' },
      cwd: { type: 'string', description: '可选：只查该工作目录的会话；不传则查全部工作目录。' },
      limit: { type: 'integer', description: `最多返回多少个会话，默认 ${DEFAULT_LIMIT}，最大 ${MAX_LIMIT}。` },
      offset: { type: 'integer', description: '翻页偏移，配合上一页返回的 nextOffset 使用。' },
      op: { type: 'string', description: '多关键词组合方式：AND（默认）或 OR。' },
      includeSubagents: { type: 'boolean', description: '是否纳入子代理会话，默认 false。' },
    },
    output: OUTPUT,
    async execute(args, exec) {
      if (disposed) return { content: '插件正在卸载，请稍后再试。' };
      const query = typeof args.query === 'string' ? args.query.trim() : '';
      if (!query) return { content: '请提供要检索的关键词：query 不能为空或只有空白。' };
      try {
        const res = search(store, {
          query,
          cwd: typeof args.cwd === 'string' && args.cwd ? args.cwd : undefined,
          limit: clampInt(args.limit, DEFAULT_LIMIT, MAX_LIMIT),
          offset: clampInt(args.offset, 0, 100000),
          op: args.op === 'OR' ? 'OR' : 'AND',
          includeSubagents: args.includeSubagents === true,
          excludeSession: currentSessionId(exec),
        });
        return { content: publish(renderSearch(res, query), res.privacy) };
      } catch {
        // R2-2：dispose 竞态下在途调用可能撞已关闭句柄，返回友好提示而非崩溃
        return { content: '索引暂不可用（可能正在卸载或重建），请稍后再试。' };
      }
    },
  }));

  ctx.tools.register(defineTool({
    name: 'recall_read',
    description:
      '读取一个历史会话的对话原文窗口（含被压缩遮蔽的旧内容）。默认给最近 30 条；' +
      '要从更早处连续读时传 fromSeq（上次输出会给下一段起点）。includeTools=true 时连同工具调用与结果一起读。',
    parameters: {
      sessionId: { type: 'string', required: true, description: 'recall_search / recall_list 给出的会话 id。' },
      last: { type: 'integer', description: '读最近多少条对话，默认 30，最大 200。' },
      fromSeq: { type: 'integer', description: '从该 seq（含）往后读；不传则读最近 last 条。' },
      maxChars: { type: 'integer', description: '输出字符上限，默认 8000，最大 20000。' },
      includeTools: { type: 'boolean', description: '是否包含工具调用/结果，默认 false。' },
      includeSubagents: { type: 'boolean', description: '是否允许读取子代理会话，默认 false（与 search/list 策略一致）。' },
    },
    output: OUTPUT,
    async execute(args) {
      if (disposed) return { content: '插件正在卸载，请稍后再试。' };
      const sessionId = typeof args.sessionId === 'string' ? args.sessionId.trim() : '';
      if (!sessionId) return { content: '请提供 sessionId。' };
      // 隐私：标题读不出或带私密标记 ⇒ 失败关闭，整段拒绝
      let title = null;
      try {
        const r = await ctx.sessionQuery.readTitleSnapshots([sessionId]);
        if (r?.[0]?.status === 'fulfilled') title = r[0].value?.title?.title ?? '';
      } catch { /* null */ }
      if (title === null) return { content: '该会话标题读不出来，无法判定私密标记，已按私密处理拒绝读取。' };
      if (isPrivateTitle(title)) return { content: '该会话带私密标记，已整段排除，不可读取。' };

      let snap;
      try {
        snap = await ctx.sessionQuery.readSession(sessionId);
      } catch (e) {
        return { content: `读取会话失败：${String(e?.message ?? e).slice(0, 200)}` };
      }
      // R2-7：会话头缺失时失败关闭（不??0 放行子代理）
      if (!snap || !snap.session) {
        return { content: '读取会话失败：会话头缺失，无法判定子代理属性，已按失败关闭拒绝。' };
      }
      // 修 B8：子代理会话默认拒读，与 search/list 策略对齐（跨工作区是有意设计，不在此限）
      if (args.includeSubagents !== true && (snap.session?.delegationDepth ?? 0) > 0) {
        return { content: '该会话是子代理会话，默认不读取；如确需读取传 includeSubagents=true。' };
      }
      // R3-6：事件列表缺失/非数组 ⇒ 失败关闭；整体外层 try/catch 与 search/list 降级对称。
      if (!Array.isArray(snap.events)) {
        return { content: '读取会话失败：事件列表缺失或格式异常，已按失败关闭拒绝。' };
      }
      try {
        const includeTools = args.includeTools === true;
        const maxChars = clampInt(args.maxChars, 8000, 20000);
        const items = [];
        for (const ev of snap.events) {
          const t = ev.type;
          const isMsg = t === 'user/message' || t === 'assistant/message';
          const isTool = t === 'tool/call' || t === 'tool/result';
          if (!isMsg && !(includeTools && isTool)) continue;
          const text = extractEventText(ev);
          if (!text) continue;
          const who = t === 'user/message' ? '用户' : t === 'assistant/message' ? '助手' : t === 'tool/call' ? '工具调用' : '工具结果';
          items.push({ seq: ev.seq ?? 0, text: `${who}：${text}` });
        }
        const fromSeq = Number.isFinite(Number(args.fromSeq)) ? Number(args.fromSeq) : null;
        let chosen;
        if (fromSeq != null) chosen = items.filter((i) => i.seq >= fromSeq);
        else chosen = items.slice(-clampInt(args.last, 30, 200));
        let redacted = 0;
        const lines = [];
        let used = 0;
        let nextFrom = null;
        for (const i of chosen) {
          const r = redactDeep(normalizeForRedact(i.text)); // R2-4/R3-3/R3-7：出口与入库同口径（折半角/去零宽/净化→迭代打码）
          redacted += r.count;
          if (used + r.text.length > maxChars) { nextFrom = i.seq; break; }
          lines.push(`[seq ${i.seq}] ${r.text}`);
          used += r.text.length;
        }
        const head = `会话「${title || '(无标题)'}」[${sessionId}]，共 ${items.length} 条可读对话。`;
        const tail = nextFrom != null ? `\n…（超长截断，下一段传 fromSeq=${nextFrom}）` : '';
        return { content: publish(`${head}\n\n${lines.join('\n\n')}${tail}`, { redacted }) };
      } catch {
        return { content: '读取会话暂不可用（可能正在卸载或数据异常），请稍后再试。' };
      }
    },
  }));

  ctx.tools.register(defineTool({
    name: 'recall_restore',
    description:
      '回源还原某条被打码事件的原始文本（不从索引取，索引里只有占位符）。须显式 confirmUnmasked=true 才返回明文；' +
      '私密标题/标题读不出/子代理会话/会话头或事件缺失一律失败关闭。本工具不保存任何原值映射（无台账），' +
      '还原结果仅当次返回，不写回索引。',
    parameters: {
      sessionId: { type: 'string', required: true, description: 'recall_search / recall_list / recall_read 给出的会话 id。' },
      seq: { type: 'integer', required: true, description: '要还原的事件序号（seq）。' },
      confirmUnmasked: { type: 'boolean', required: true, description: '必须显式传 true 才返回明文；不传或 false 一律拒绝，不返回原文。' },
    },
    output: OUTPUT,
    async execute(args) {
      if (disposed) return { content: '插件正在卸载，请稍后再试。' };
      const sessionId = typeof args.sessionId === 'string' ? args.sessionId.trim() : '';
      if (!sessionId) return { content: '请提供 sessionId。' };
      const seq = Number(args.seq);
      if (!Number.isFinite(seq)) return { content: '请提供有效的 seq。' };
      // 门控一：未显式授权 ⇒ 拒绝，不返明文（不读源、不回源）。
      if (args.confirmUnmasked !== true) {
        return { content: '未显式授权（confirmUnmasked 必须为 true），已拒绝返回明文。确认该会话不含私密内容后再重试。' };
      }
      // 门控二：私密标题失败关闭（沿用 recall_read 口径）。
      let title = null;
      try {
        const r = await ctx.sessionQuery.readTitleSnapshots([sessionId]);
        if (r?.[0]?.status === 'fulfilled') title = r[0].value?.title?.title ?? '';
      } catch { /* null */ }
      if (title === null) return { content: '该会话标题读不出来，无法判定私密标记，已按私密处理拒绝还原。' };
      if (isPrivateTitle(title)) return { content: '该会话带私密标记，已整段排除，不可还原。' };

      let snap;
      try {
        snap = await ctx.sessionQuery.readSession(sessionId);
      } catch (e) {
        return { content: `读取会话失败：${String(e?.message ?? e).slice(0, 200)}` };
      }
      // 门控三：会话头缺失/事件列表缺失 ⇒ 失败关闭。
      if (!snap || !snap.session) {
        return { content: '读取会话失败：会话头缺失，无法判定子代理属性，已按失败关闭拒绝。' };
      }
      if ((snap.session?.delegationDepth ?? 0) > 0) {
        return { content: '该会话是子代理会话，默认不还原。' };
      }
      if (!Array.isArray(snap.events)) {
        return { content: '读取会话失败：事件列表缺失或格式异常，已按失败关闭拒绝。' };
      }
      const ev = snap.events.find((e) => (e.seq ?? 0) === seq);
      if (!ev) return { content: `未找到 seq=${seq} 的事件（可能已被压缩或不在当前会话内）。` };
      const text = extractEventText(ev);
      if (!text) return { content: `seq=${seq} 无可还原的文本内容。` };
      const MAX_RESTORE_CHARS = 20000;
      const body = text.length > MAX_RESTORE_CHARS ? text.slice(0, MAX_RESTORE_CHARS) + '\n…（超长截断）' : text;
      return { content: publish(`会话「${title || '(无标题)'}」[${sessionId}] seq=${seq}（${ev.type}）回源原文：\n\n${body}`) };
    },
  }));

  ctx.tools.register(defineTool({
    name: 'recall_list',
    description: '列出历史会话清单（标题、时间、工作目录），默认跨全部工作目录、按创建时间倒序、不含子代理会话。',
    parameters: {
      cwd: { type: 'string', description: '可选：只列该工作目录的会话。' },
      limit: { type: 'integer', description: '最多列多少个，默认 20，最大 100。' },
      includeSubagents: { type: 'boolean', description: '是否纳入子代理会话，默认 false。' },
    },
    output: OUTPUT,
    async execute(args) {
      if (disposed) return { content: '插件正在卸载，请稍后再试。' };
      const limit = clampInt(args.limit, 20, 100);
      const cwd = typeof args.cwd === 'string' && args.cwd ? args.cwd.replace(/[\\/]+$/u, '').toLowerCase() : null;
      try {
        const rows = store.db.prepare('SELECT * FROM sessions ORDER BY created_at DESC').all();
        const lines = [];
        let hidden = 0, unread = 0;
        for (const r of rows) {
          if (lines.length >= limit) break;
          if (!args.includeSubagents && r.delegation_depth > 0) continue;
          if (cwd && String(r.cwd).replace(/[\\/]+$/u, '').toLowerCase() !== cwd) continue;
          if (r.title == null) { unread++; continue; }
          if (isPrivateTitle(r.title)) { hidden++; continue; }
          lines.push(`- ${fmtTime(r.created_at)} · ${r.title || '(无标题)'} · [${r.session_id}] · ${r.cwd} · ${r.doc_count} 段`);
        }
        const body = lines.length ? lines.join('\n') : '没有符合条件的会话。';
        return { content: publish(`${body}\n\n${coverageNote(store)}`, { hidden, unreadable: unread }) };
      } catch {
        return { content: '索引暂不可用（可能正在卸载或重建），请稍后再试。' }; // R2-2
      }
    },
  }));
}