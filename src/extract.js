// 事件语义文本提取：忠实移植官方 @deepseek-ai/dsh-session-query extraction.ts 的口径。
// 入索引范围与官方一致：user/message 正文、assistant/message 正文（reasoning 排除）、
// tool/call 名+参数、tool/result 内容+错误名码、todo/write、turn/end 错误。
// 结构事件与未知事件不入索引。P2 在宿主内可切换为官方公开导出 buildSessionEventSearchDocuments，
// 本移植作为独立运行与兜底路径，口径已逐行对照。

function joinText(parts) {
  return parts.map((p) => (typeof p === 'string' ? p.trim() : '')).filter(Boolean).join('\n');
}

function isRecallName(name) {
  return /^recall_/.test(String(name ?? ''));
}

function blockText(block) {
  if (!block || typeof block !== 'object') return [];
  switch (block.type) {
    case 'text':
      return typeof block.text === 'string' ? [block.text] : [];
    case 'reasoning':
      return [];
    case 'tool-call':
      return [block.name, block.arguments];
    default:
      return [];
  }
}

// 0.3.0 / R10-4：message content 数组内 type:'tool-call' 块若是本插件 recall_* 族
// （含 recall_search/read/list/restore），先从内容里剔除再入索引——否则 assistant 正文里的
// 自产调用名+参数不经 event 级 provenance 跳过，会把检索摘录回声再写回索引。
function filterRecallBlocks(content) {
  if (!Array.isArray(content)) return content;
  return content.filter((b) => !(b && b.type === 'tool-call' && isRecallName(b.name)));
}

function contentText(content) {
  const c = filterRecallBlocks(content);
  if (!Array.isArray(c)) return typeof c === 'string' ? c.trim() : '';
  return joinText(c.flatMap(blockText));
}

function turnEndText(reason) {
  if (!reason || typeof reason !== 'object') return '';
  switch (reason.kind) {
    case 'error':
      return joinText(['error', reason.error?.message ?? '']);
    case 'aborted':
      return 'aborted';
    case 'max-tokens':
    case 'interrupted':
      return reason.kind;
    default:
      return '';
  }
}

/** 提取一个事件的可搜索文本；不可搜索返回空串。 */
export function extractEventText(ev) {
  const d = ev?.data ?? {};
  switch (ev?.type) {
    case 'user/message':
      return contentText(d.content);
    case 'assistant/message':
      return contentText(d.message?.content);
    case 'tool/call':
      return joinText([d.name, d.arguments]);
    case 'tool/result':
      return joinText([contentText(d.message?.content), d.error?.name ?? '', d.error?.code ?? '']);
    case 'todo/write':
      return joinText((Array.isArray(d.todos) ? d.todos : []).flatMap((t) => [t?.status, t?.content]));
    case 'turn/end':
      return turnEndText(d.reason);
    default:
      return '';
  }
}

/** 把事件流折成入索引文档：{seq, type, time, text}，空文本事件丢弃。
 *  自污染闭环（路线图1）：本插件自己的 recall_* tool/call 与 tool/result 不入索引——
 *  否则检索摘录会被后续会话再记录、再入库，形成回声室＋凭据材料再生（R9-1 根因）＋索引膨胀。
 *  tool/result 不带 callId/name（meta 实测为空），用 (turn,step) 配对；仅当该 step 的全部
 *  tool/call 都是 recall_* 时才跳过其 result，避免误伤同 step 并行其它工具的结果。
 *  混合 step / 它插件摘录（palimpsest_search/mnemon_recall/裸 recall legacy）不由 provenance 跳，
 *  凭据材料由 0.3.0 拒止式打码兜底。 */
export function buildDocs(events) {
  const stepCalls = new Map(); // key turn:step -> {total, recall}
  for (const ev of events) {
    if (ev?.type !== 'tool/call') continue;
    const key = `${ev?.data?.turn ?? 0}:${ev?.data?.step ?? 0}`;
    const s = stepCalls.get(key) ?? { total: 0, recall: 0 };
    s.total++;
    if (isRecallName(ev?.data?.name)) s.recall++;
    stepCalls.set(key, s);
  }
  const isOwnResult = (ev) => {
    const s = stepCalls.get(`${ev?.data?.turn ?? 0}:${ev?.data?.step ?? 0}`);
    return !!s && s.total > 0 && s.recall === s.total;
  };
  const docs = [];
  for (const ev of events) {
    if (ev?.type === 'tool/call' && isRecallName(ev?.data?.name)) continue;
    if (ev?.type === 'tool/result' && isOwnResult(ev)) continue;
    const text = extractEventText(ev);
    if (!text) continue;
    docs.push({ seq: ev.seq ?? 0, type: ev.type, time: ev.time ?? 0, text });
  }
  return docs;
}
