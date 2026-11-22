// 两段式检索（0.1.4）。契约对齐 plugin.js：返回 hits(snippet 对象)/total/fallbackUsed/nextOffset/coverage/privacy。
// R2-9 标点/符号查询走子串精确；R2-10 单关键词 FTS 用 SQL 分组聚合；B6/N6 AND 会话级；
// N3 摘录命中任一词；B9 摘录代理对对齐；B3 出口摘录打码；隐私过滤（null 标题失败关闭）在搜索层完成。
// R4-7：摘录出口与 read 同口径套 normalizeForRedact（折半角/去零宽/净化→打码），防御对称。

import { buildMatch, keywordsOf, isRisky, foldWidth, normalizeForRedact } from './tokenize.js';
import { privacyFilter, redactDeep } from './privacy.js';

export function snippetAround(rawText, keyword, radius = 60) {
  const text = String(rawText);
  const kw = foldWidth(String(keyword));
  // R11-4：纯 CJK/符号词无大小写，免全文 toLowerCase 拷贝；含 ASCII 字母数字才归一比对。
  const hay = /[A-Za-z0-9]/u.test(kw) ? text.toLowerCase() : text;
  const idx = hay.indexOf(kw.toLowerCase());
  let start;
  let end;
  if (idx < 0) {
    start = 0;
    end = Math.min(text.length, radius * 2);
  } else {
    start = Math.max(0, idx - radius);
    end = Math.min(text.length, idx + String(keyword).length + radius);
  }
  if (start > 0 && start < text.length) {
    const c = text.charCodeAt(start);
    if (c >= 0xdc00 && c <= 0xdfff) start++;
  }
  if (end > 0 && end < text.length) {
    const c = text.charCodeAt(end - 1);
    if (c >= 0xd800 && c <= 0xdbff) end--;
  }
  return `${start > 0 ? '…' : ''}${text.slice(start, end)}${end < text.length ? '…' : ''}`;
}

function intersect(sets) {
  if (!sets.length) return new Set();
  let acc = sets[0];
  for (let i = 1; i < sets.length; i++) {
    const next = new Set();
    for (const id of acc) if (sets[i].has(id)) next.add(id);
    acc = next;
  }
  return acc;
}

export function search(store, opts = {}) {
  const {
    query = '', limit = 10, offset = 0, op = 'AND', includeSubagents = false,
    cwd, excludeSession, types, timeFrom, timeTo, unreadable: unreadableOpt,
  } = opts;
  const kws = keywordsOf(query);
  const risky = isRisky(query);
  const operator = op === 'OR' ? 'OR' : 'AND';
  const coverage = {
    indexedSessions: store.counts().sessions,
    totalSessions: Number(store.getMeta('totalSessions') ?? 0),
    lastSyncAt: Number(store.getMeta('lastSyncAt') ?? 0),
    lastSyncError: store.getMeta('lastSyncError') || '',
  };
  const base = { hits: [], total: 0, fallbackUsed: risky, nextOffset: null, coverage, privacy: { redacted: 0, hidden: 0, unreadable: 0, hiddenIds: [], unreadableIds: [] } };
  if (!kws.length) return base;

  const sessionMap = new Map(store.db.prepare('SELECT * FROM sessions').all().map((s) => [s.session_id, s]));
  // R3-5：cwd 归一与 recall_list 同口径（小写 + 去尾斜杠），保证 cwd 锁定承诺一致。
  const normCwd = cwd ? String(cwd).replace(/[\\/]+$/u, '').toLowerCase() : null;
  const passSession = (sid) => {
    const s = sessionMap.get(sid);
    if (!s) return false;
    if (excludeSession && sid === excludeSession) return false;
    if (!includeSubagents && s.delegation_depth > 0) return false;
    if (normCwd && String(s.cwd).replace(/[\\/]+$/u, '').toLowerCase() !== normCwd) return false;
    return true;
  };

  const groups = new Map();
  const addRows = (rows) => {
    for (const r of rows) {
      if (!passSession(r.session_id)) continue;
      const g = groups.get(r.session_id) ?? { bestScore: Infinity, latestTime: 0, matchCount: 0 };
      g.bestScore = Math.min(g.bestScore, r.score);
      g.latestTime = Math.max(g.latestTime, r.time ?? 0);
      g.matchCount++;
      groups.set(r.session_id, g);
    }
  };

  let fallbackUsed = risky;
  if (risky) {
    if (kws.length === 1) {
      // R11-4：单 risky 词走 SQL 分组聚合单次扫描，不再二次全表拉全行水合。
      for (const g of store.substringGroups(kws[0])) {
        if (!passSession(g.session_id)) continue;
        groups.set(g.session_id, { bestScore: Infinity, latestTime: g.latest, matchCount: g.cnt });
      }
    } else if (operator === 'AND' && kws.length > 1) {
      const inter = intersect(kws.map((kw) => new Set(store.substringSessions(kw))));
      addRows(store.substringAllMulti(kws, 'OR').filter((r) => inter.has(r.session_id)));
    } else {
      addRows(store.substringAllMulti(kws, operator));
    }
  } else if (kws.length === 1) {
    const match = buildMatch(kws[0], 'AND');
    const g = match ? store.ftsGroups(match) : [];
    if (g.length === 0) {
      fallbackUsed = true;
      addRows(store.substringAllMulti(kws, 'AND'));
    } else {
      for (const row of g) {
        if (!passSession(row.session_id)) continue;
        groups.set(row.session_id, { bestScore: row.best, latestTime: row.latest, matchCount: row.cnt });
      }
    }
  } else if (operator === 'OR') {
    const match = buildMatch(query, 'OR');
    const rows = match ? store.ftsAll(match) : [];
    if (rows.length === 0) {
      fallbackUsed = true;
      addRows(store.substringAllMulti(kws, 'OR'));
    } else addRows(rows);
  } else {
    const inter = intersect(kws.map((kw) => {
      const m = buildMatch(kw, 'AND');
      return new Set(m ? store.ftsSessions(m) : []);
    }));
    if (inter.size === 0) {
      fallbackUsed = true;
      const sInter = intersect(kws.map((kw) => new Set(store.substringSessions(kw))));
      addRows(store.substringAllMulti(kws, 'OR').filter((r) => sInter.has(r.session_id)));
    } else {
      const match = buildMatch(query, 'OR');
      addRows((match ? store.ftsAll(match) : []).filter((r) => inter.has(r.session_id)));
    }
  }

  const ranked = [...groups.entries()].sort((a, b) =>
    fallbackUsed ? b[1].latestTime - a[1].latestTime : a[1].bestScore - b[1].bestScore,
  );

  // 隐私过滤：null 标题失败关闭 + 调用方显式 unreadable 集合 + 私密标记整段排除
  const unreadableSet = new Set(unreadableOpt ?? []);
  for (const [sid] of ranked) if (sessionMap.get(sid)?.title == null) unreadableSet.add(sid);
  const entries = ranked.map(([sid, g]) => ({ sessionId: sid, title: sessionMap.get(sid)?.title ?? null, g }));
  const { visible, hidden, unreadable, hiddenIds, unreadableIds } = privacyFilter(entries, unreadableSet);
  const total = visible.length;
  const page = visible.slice(offset, offset + limit);
  const nextOffset = offset + limit < total ? offset + limit : null;

  const filter = { types, timeFrom, timeTo };
  const useSub = risky || fallbackUsed;
  const snippetMatch = useSub ? null : buildMatch(query, 'OR');

  // R3-10：批量预取本页所有会话的摘录（一次查询），消除每会话一次查询的 N+1。
  const pageIds = page.map((e) => e.sessionId);
  const docRows = useSub
    ? store.substringSessionDocsBatch(kws, pageIds, 3, filter)
    : store.ftsSessionDocsBatch(snippetMatch, pageIds, 3, filter);
  const docsBySession = new Map();
  for (const d of docRows) {
    const arr = docsBySession.get(d.session_id) ?? [];
    arr.push(d);
    docsBySession.set(d.session_id, arr);
  }

  const hits = [];
  let redacted = 0;
  for (const { sessionId: sid, g } of page) {
    const sess = sessionMap.get(sid);
    const docs = docsBySession.get(sid) ?? [];
    const snippets = docs.map((d) => {
      // R11-4：不再对全文 raw_text 反复 toLowerCase 找命中词；兜底取首词，摘录定位由 snippetAround 内部完成。
      const kw = kws[0];
      const r = redactDeep(normalizeForRedact(snippetAround(d.raw_text, kw))); // R4-7：出口与入库/read 同口径
      redacted += r.count;
      return { seq: d.seq, type: d.type, time: d.time, text: r.text };
    });
    hits.push({
      sessionId: sid,
      title: sess.title,
      cwd: sess.cwd,
      createdAt: sess.created_at,
      isSubagent: sess.delegation_depth > 0,
      partial: !!sess.partial,
      matchCount: g.matchCount,
      latestTime: g.latestTime,
      snippets,
    });
  }
  return { hits, total, fallbackUsed, nextOffset, coverage, privacy: { redacted, hidden, unreadable, hiddenIds, unreadableIds } };
}