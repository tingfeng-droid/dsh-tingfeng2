// 宿主内会话源（P2 主路径）：只消费官方「与后端无关」的读取契约。
// 枚举走 ctx.sessionQuery.listSessions；内容走 readSession（重放校验、格式解析归官方）；
// 标题走 readTitleSnapshots，读不出 ⇒ title=null ⇒ 查询层失败关闭按私密处理。
// 指纹复用文件 stat（便宜）；无文件的 live 会话每次同步都重读（保证新鲜）。
// 官方搜索后端怎么演进都与本源无关——我们不碰 searchSessions/索引/游标。

import { FileSessionSource } from './source-file.js';

export class ServiceSessionSource {
  constructor(ctx, fileSource = new FileSessionSource()) {
    this.sq = ctx.sessionQuery;
    this.files = fileSource;
  }

  async list() {
    const records = await this.sq.listSessions();
    const fileEntries = await this.files.list();
    const byId = new Map(fileEntries.map((e) => [e.dirId, e]));
    return records.map((r) => {
      const id = r.header.id;
      const fe = byId.get(id);
      return {
        dirId: id,
        file: fe?.file ?? null,
        fingerprint: fe ? fe.fingerprint : `live:${id}:${Date.now()}`,
      };
    });
  }

  async read(entry) {
    const snap = await this.sq.readSession(entry.dirId);
    // 子代理会话继承的父会话前缀不入索引，避免跨会话重复命中
    const inherited = snap.inheritedEventCount ?? 0;
    const events = inherited > 0 ? snap.events.slice(inherited) : snap.events;
    let title = null; // null = 读不出（失败关闭）；'' = 日志里还没有标题事件
    try {
      const res = await this.sq.readTitleSnapshots([entry.dirId]);
      const r0 = res?.[0];
      if (r0?.status === 'fulfilled') title = r0.value?.title?.title ?? '';
    } catch {
      // 保持 null
    }
    return { header: snap.session, title, events, partial: false, fingerprint: entry.fingerprint };
  }
}