// 中文双字滑窗分词 + 查询归一化（0.1.3）。
// B5 CJK 补空格；B12 buildMatch 引短语数据化；B14 全角字母数字折半角；
// B15/R2-11 孤立代理净化 U+FFFD；R2-9 isRisky 放宽 NON_WORD；
// R2-6/R3-8 零宽表补 U+2060/180E/方向标记 200E/200F/202A-202E，连字符 U+2010/2011 折 '-'。
// R3-3/R3-7：normalizeForRedact 统一入库/出口打码前归一（折半角→去零宽→净化），净化先于打码。

const CJK_RUN = /[㐀-䶿一-鿿豈-﫿]+/g;
const CJK_CHAR = /[㐀-䶿一-鿿豈-﫿]/;
const FULLWIDTH = /[！-～]/g;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
const NON_WORD = /[^㐀-䶿一-鿿豈-﫿A-Za-z0-9\s]/u;
const REPLACEMENT_CHAR = String.fromCharCode(0xfffd); // U+FFFD（R2-11：杜绝误用 U+FEFF）

// 零宽/方向标记剥离表（用码点构造，避免不可见字面量误写）：200B-200F、202A-202E、2060、180E、FEFF。
const ZERO_WIDTH = new RegExp(
  '[' +
    String.fromCharCode(0x200b) + '-' + String.fromCharCode(0x200f) +
    String.fromCharCode(0x202a) + '-' + String.fromCharCode(0x202e) +
    String.fromCharCode(0x2060) + String.fromCharCode(0x180e) + String.fromCharCode(0xfeff) +
  ']',
  'g',
);
// R3-8：U+2010/U+2011 连字符折半角 '-'（不在 FF01-FF5E 全角区）。
const DASHES = new RegExp('[' + String.fromCharCode(0x2010) + String.fromCharCode(0x2011) + ']', 'g');

export function foldWidth(text) {
  return String(text)
    .replace(FULLWIDTH, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xfee0))
    .replace(DASHES, '-');
}

/** 孤立代理对替换为 U+FFFD（替换字符），不是 U+FEFF（零宽 BOM）。 */
export function sanitizeSurrogates(text) {
  return String(text).replace(LONE_SURROGATE, REPLACEMENT_CHAR);
}

export function stripZeroWidth(text) {
  return String(text).replace(ZERO_WIDTH, '');
}

/** 打码前统一归一（R3-3/R3-7）：折半角 → 去零宽 → 净化代理对，保证凭据连续性，入库与出口同口径。 */
export function normalizeForRedact(text) {
  return sanitizeSurrogates(stripZeroWidth(foldWidth(String(text))));
}

export function bigramRun(run) {
  if (run.length <= 1) return run;
  const out = [];
  for (let i = 0; i + 1 < run.length; i++) out.push(run.slice(i, i + 2));
  return out.join(' ');
}

export function normalizeText(text) {
  return String(text)
    .replace(CJK_RUN, (run) => ' ' + bigramRun(run) + ' ')
    // 0.2.0 路线图3：英文复合词词边界感知——整 token 保留＋按驼峰/字母数字边界拆子词一并入索引，
    // 使 schema20/sqlite3/OrderService2024 能被 schema/sqlite/order 召回（整词查询仍精确）。
    .replace(/[A-Za-z0-9]+/g, (run) => {
      const parts = run.split(/(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])/);
      return parts.length > 1 ? `${run} ${parts.join(' ')}` : run;
    });
}

export function hasCjk(text) {
  return CJK_CHAR.test(text);
}

export function preprocessQuery(query) {
  return stripZeroWidth(foldWidth(sanitizeSurrogates(String(query))));
}

export function keywordsOf(query) {
  return preprocessQuery(query).trim().split(/\s+/).filter(Boolean);
}

export function buildMatch(query, op = 'AND') {
  const kws = keywordsOf(query);
  if (!kws.length) return null;
  const parts = kws.map((kw) => `"${normalizeText(kw).trim().replaceAll('"', '""')}"`);
  return parts.join(op === 'OR' ? ' OR ' : ' AND ');
}

export function isRisky(query) {
  const q = preprocessQuery(query);
  const kws = q.trim().split(/\s+/).filter(Boolean);
  if (kws.some((k) => hasCjk(k) && [...k].length === 1)) return true;
  return NON_WORD.test(q);
}

export function firstKeyword(query) {
  return keywordsOf(query)[0] ?? '';
}