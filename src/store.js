// 旁路索引库（0.4.8，schema 32）：自己的文件/application_id/schema，绝不碰官方 sessions.sqlite。
// B3：入库即打码。R3-3：净化先于打码（normalizeForRedact），凭据字符类容 FFFD，孤立代理切断仍打码。
// B1：标题 NULL 原样入库。B15/R2-11：净化替换字符 U+FFFD。R3-9：cleanForIndex 防 null 入参。
// R2-10：ftsGroups 分组聚合下推 SQL。R3-10：摘录批量预取（窗口函数 top-N/会话），消除 N+1。
// R4-8：top-N 并列加次级排序键 seq（确定性翻页）。R3-10：摘录 CTE 先选 rowid 再回表取 raw_text，避免物化全量正文降延迟。
// B6/N6：ftsSessions/substringSessions 支持会话级 AND。R3-11：#normTerm 补 stripZeroWidth。O2：app=0 旧版本库守卫。

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { normalizeText, foldWidth, stripZeroWidth, sanitizeSurrogates, normalizeForRedact } from './tokenize.js';
import { redact, redactDeep } from './privacy.js';

const APP_ID = 0x52434c4c; // 'RCLL'
const SCHEMA_VERSION = 32; // 0.4.8：脏判定后骨架复核（-match/-replace 族、sed 站点词表/正则骨架无实值仍豁免）⇒ 行为变更，guard 须认得

/** 入库文本处理（R3-3/R3-9）：防 null → 折半角/去零宽/净化（normalizeForRedact）→ 迭代凭据打码。 */
export function cleanForIndex(text) {
  if (text == null) return '';
  return redactDeep(normalizeForRedact(text)).text;
}

export class RecallStore {
  constructor(dbPath) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.dbPath = dbPath;
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;');
    this.#guard();
    this.#migrate();
  }

  #guard() {
    const app = this.db.prepare('PRAGMA application_id').get().application_id;
    const ver = this.db.prepare('PRAGMA user_version').get().user_version;
    if (app !== 0 && app !== APP_ID) {
      throw new Error(`foreign database (application_id=${app}), refuse to open: ${this.dbPath}`);
    }
    // O2：app=0 但带旧版本号（非本插件全新库）也按不兼容重建，避免残留旧表结构。
    if ((app === APP_ID && ver !== SCHEMA_VERSION) || (app === 0 && ver !== 0 && ver !== SCHEMA_VERSION)) {
      // R5-5：DROP docs 时 SQLite 自动清其 sqlite_sequence 行（内部表不可直接 DROP），无遗留序列。
      this.db.exec('DROP TABLE IF EXISTS docs_fts; DROP TABLE IF EXISTS docs; DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS meta;');
    }
    this.db.exec(`PRAGMA application_id = ${APP_ID}; PRAGMA user_version = ${SCHEMA_VERSION};`);
  }

  #migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions(
        session_id TEXT PRIMARY KEY,
        cwd TEXT, created_at INTEGER, parent_session TEXT,
        delegation_depth INTEGER, title TEXT,
        fingerprint TEXT, event_count INTEGER, doc_count INTEGER,
        indexed_at INTEGER, partial INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS docs(
        rowid INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL, seq INTEGER, type TEXT, time INTEGER,
        raw_text TEXT, token_text TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_docs_session ON docs(session_id);
      CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(
        token_text, content='docs', content_rowid='rowid', tokenize='unicode61'
      );
      CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
    `);
    this._stmts = {
      oldDocs: this.db.prepare('SELECT rowid, token_text FROM docs WHERE session_id = ?'),
      delFts: this.db.prepare("INSERT INTO docs_fts(docs_fts, rowid, token_text) VALUES('delete', ?, ?)"),
      delDocs: this.db.prepare('DELETE FROM docs WHERE session_id = ?'),
      insDoc: this.db.prepare('INSERT INTO docs(session_id, seq, type, time, raw_text, token_text) VALUES(?,?,?,?,?,?)'),
      insFts: this.db.prepare('INSERT INTO docs_fts(rowid, token_text) VALUES(?, ?)'),
      upsertSession: this.db.prepare(`
        INSERT INTO sessions(session_id, cwd, created_at, parent_session, delegation_depth, title,
                             fingerprint, event_count, doc_count, indexed_at, partial)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(session_id) DO UPDATE SET
          cwd=excluded.cwd, created_at=excluded.created_at, parent_session=excluded.parent_session,
          delegation_depth=excluded.delegation_depth, title=excluded.title, fingerprint=excluded.fingerprint,
          event_count=excluded.event_count, doc_count=excluded.doc_count, indexed_at=excluded.indexed_at,
          partial=excluded.partial
      `),
      delSession: this.db.prepare('DELETE FROM sessions WHERE session_id = ?'),
      fingerprints: this.db.prepare('SELECT session_id, fingerprint FROM sessions'),
      ftsAll: this.db.prepare(`
        SELECT d.session_id, d.seq, d.type, d.time, bm25(docs_fts) AS score
        FROM docs_fts JOIN docs d ON d.rowid = docs_fts.rowid WHERE docs_fts MATCH ?
      `),
      ftsGroups: this.db.prepare(`
        WITH m AS MATERIALIZED (
          SELECT d.session_id AS session_id, bm25(docs_fts) AS score, d.time AS time
          FROM docs_fts JOIN docs d ON d.rowid = docs_fts.rowid WHERE docs_fts MATCH ?
        )
        SELECT session_id, min(score) AS best, max(time) AS latest, count(*) AS cnt
        FROM m GROUP BY session_id
      `),
      ftsSessions: this.db.prepare(`
        SELECT DISTINCT d.session_id AS session_id
        FROM docs_fts JOIN docs d ON d.rowid = docs_fts.rowid WHERE docs_fts MATCH ?
      `),
      counts: this.db.prepare('SELECT (SELECT count(*) FROM sessions) AS sessions, (SELECT count(*) FROM docs) AS docs'),
      setMeta: this.db.prepare('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
      getMeta: this.db.prepare('SELECT value FROM meta WHERE key = ?'),
    };
  }

  replaceSession(meta, docs) {
    const s = this._stmts;
    const title = meta.title == null ? null : cleanForIndex(meta.title);
    this.db.exec('BEGIN');
    try {
      for (const old of s.oldDocs.all(meta.sessionId)) s.delFts.run(old.rowid, old.token_text);
      s.delDocs.run(meta.sessionId);
      for (const doc of docs) {
        const clean = cleanForIndex(doc.text);
        if (!clean) continue;
        const token = normalizeText(clean);
        const r = s.insDoc.run(meta.sessionId, doc.seq, doc.type, doc.time, clean, token);
        s.insFts.run(Number(r.lastInsertRowid), token);
      }
      s.upsertSession.run(
        meta.sessionId, meta.cwd ?? '', meta.createdAt ?? 0, meta.parentSession ?? '',
        meta.delegationDepth ?? 0, title, meta.fingerprint ?? '',
        meta.eventCount ?? 0, docs.length, Date.now(), meta.partial ? 1 : 0,
      );
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  removeSession(sessionId) {
    const s = this._stmts;
    this.db.exec('BEGIN');
    try {
      for (const old of s.oldDocs.all(sessionId)) s.delFts.run(old.rowid, old.token_text);
      s.delDocs.run(sessionId);
      s.delSession.run(sessionId);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  fingerprints() {
    const map = new Map();
    for (const row of this._stmts.fingerprints.all()) map.set(row.session_id, row.fingerprint);
    return map;
  }

  ftsAll(matchExpr) {
    return this._stmts.ftsAll.all(matchExpr);
  }

  /** SQL 侧分组聚合（R2-10）：返回 ≤会话数 行，避免大结果集拉全行到 JS。 */
  ftsGroups(matchExpr) {
    return this._stmts.ftsGroups.all(matchExpr);
  }

  ftsSessions(matchExpr) {
    return this._stmts.ftsSessions.all(matchExpr).map((r) => r.session_id);
  }

  #normTerm(t) {
    return stripZeroWidth(foldWidth(sanitizeSurrogates(String(t)))).toLowerCase();
  }

  substringSessions(term) {
    const t = this.#normTerm(term);
    if (!t) return [];
    return this.db.prepare('SELECT DISTINCT session_id FROM docs WHERE instr(lower(raw_text), ?) > 0').all(t).map((r) => r.session_id);
  }

  /** R11-4：单 risky 词兜底——SQL 侧一次扫描 GROUP BY 会话聚合，避免二次全表扫描＋全量行 JS 水合。 */
  substringGroups(term) {
    const t = this.#normTerm(term);
    if (!t) return [];
    // 纯 CJK/符号词无大小写，跳过 lower() 函数逐行开销；含 ASCII 字母数字才归一比对。
    const where = /[A-Za-z0-9]/u.test(t) ? 'instr(lower(raw_text), ?) > 0' : 'instr(raw_text, ?) > 0';
    return this.db.prepare(`SELECT session_id, max(time) AS latest, count(*) AS cnt FROM docs WHERE ${where} GROUP BY session_id`).all(t);
  }

  substringAllMulti(terms, op = 'AND') {
    const clean = terms.map((t) => this.#normTerm(t)).filter(Boolean);
    if (!clean.length) return [];
    const cond = clean.map(() => 'instr(lower(raw_text), ?) > 0').join(op === 'OR' ? ' OR ' : ' AND ');
    return this.db.prepare(`SELECT session_id, seq, type, time, 0.0 AS score FROM docs WHERE ${cond}`).all(...clean);
  }

  #docFilter(filter = {}) {
    let sql = '';
    const params = [];
    if (filter.types?.length) {
      sql += ` AND d.type IN (${filter.types.map(() => '?').join(',')})`;
      params.push(...filter.types);
    }
    if (filter.timeFrom != null) { sql += ' AND d.time >= ?'; params.push(filter.timeFrom); }
    if (filter.timeTo != null) { sql += ' AND d.time <= ?'; params.push(filter.timeTo); }
    return { sql, params };
  }

  ftsSessionDocs(matchExpr, sessionId, limit = 3, filter = {}) {
    const f = this.#docFilter(filter);
    return this.db.prepare(`
      SELECT d.session_id, d.seq, d.type, d.time, d.raw_text, bm25(docs_fts) AS score
      FROM docs_fts JOIN docs d ON d.rowid = docs_fts.rowid
      WHERE docs_fts MATCH ? AND d.session_id = ?${f.sql} ORDER BY score LIMIT ?
    `).all(matchExpr, sessionId, ...f.params, limit);
  }

  /** 摘录定位：命中任一关键词的文档（N3：不再仅首词）。 */
  substringSessionDocsAny(terms, sessionId, limit = 3, filter = {}) {
    const f = this.#docFilter(filter);
    const clean = terms.map((t) => this.#normTerm(t)).filter(Boolean);
    if (!clean.length) return [];
    const cond = clean.map(() => 'instr(lower(raw_text), ?) > 0').join(' OR ');
    return this.db.prepare(`
      SELECT session_id, seq, type, time, raw_text, 0.0 AS score
      FROM docs WHERE (${cond}) AND session_id = ?${f.sql} ORDER BY time DESC LIMIT ?
    `).all(...clean, sessionId, ...f.params, limit);
  }

  /** R3-10：批量预取多会话摘录（窗口函数 top-N/会话），一次查询消除 N+1。
   *  R3-10 延迟优化：CTE 只物化 rowid/seq/score（不物化全量 raw_text），选完 top-N 再回表取正文，宽泛词大结果集显著降延迟。
   *  R4-8：并列 bm25 加次级排序键 seq，翻页顺序确定。 */
  ftsSessionDocsBatch(matchExpr, sessionIds, perSession = 3, filter = {}) {
    if (!sessionIds.length) return [];
    const f = this.#docFilter(filter);
    const ph = sessionIds.map(() => '?').join(',');
    return this.db.prepare(`
      WITH m AS MATERIALIZED (
        SELECT d.session_id AS session_id, d.rowid AS rid, d.seq AS seq, bm25(docs_fts) AS score
        FROM docs_fts JOIN docs d ON d.rowid = docs_fts.rowid
        WHERE docs_fts MATCH ? AND d.session_id IN (${ph})${f.sql}
      ), r AS (
        SELECT m.*, ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY score, seq) AS rn FROM m
      )
      SELECT d.session_id AS session_id, d.seq AS seq, d.type AS type, d.time AS time, d.raw_text AS raw_text, r.score AS score
      FROM r JOIN docs d ON d.rowid = r.rid WHERE r.rn <= ?
    `).all(matchExpr, ...sessionIds, ...f.params, perSession);
  }

  substringSessionDocsBatch(terms, sessionIds, perSession = 3, filter = {}) {
    const clean = terms.map((t) => this.#normTerm(t)).filter(Boolean);
    if (!clean.length || !sessionIds.length) return [];
    const f = this.#docFilter(filter);
    // R11-4：纯 CJK/符号词无大小写，跳过 lower() 逐行函数开销；含 ASCII 字母数字才归一比对。
    const asciiTerm = clean.some((c) => /[A-Za-z0-9]/u.test(c));
    const colExpr = asciiTerm ? 'instr(lower(d.raw_text), ?) > 0' : 'instr(d.raw_text, ?) > 0';
    const cond = clean.map(() => colExpr).join(' OR ');
    const ph = sessionIds.map(() => '?').join(',');
    return this.db.prepare(`
      WITH m AS MATERIALIZED (
        SELECT d.session_id AS session_id, d.rowid AS rid, d.seq AS seq, d.time AS time
        FROM docs d WHERE (${cond}) AND d.session_id IN (${ph})${f.sql}
      ), r AS (
        SELECT m.*, ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY time DESC, seq DESC) AS rn FROM m
      )
      SELECT d.session_id AS session_id, d.seq AS seq, d.type AS type, d.time AS time, d.raw_text AS raw_text, 0.0 AS score
      FROM r JOIN docs d ON d.rowid = r.rid WHERE r.rn <= ?
    `).all(...clean, ...sessionIds, ...f.params, perSession);
  }

  counts() {
    return this._stmts.counts.get();
  }

  setMeta(key, value) {
    this._stmts.setMeta.run(key, String(value));
  }

  getMeta(key) {
    return this._stmts.getMeta.get(key)?.value;
  }

  close() {
    this.db.close();
  }
}