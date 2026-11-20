/* Расшифровывает файлы книги на лету. Ключ живёт только в памяти; при перезапуске запрашивается у открытой вкладки. */
'use strict';
const BOOK = 'book/';
let KEY = null, MAN = null, MAN_AT = 0, PENDING = null, REFRESH = null;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

function dec(key, buf) {   // без копий: iv и шифртекст — окна в тот же буфер
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(buf, 0, 12) }, key, new Uint8Array(buf, 12));
}
/* Ошибка 'net' — не дошли до сервера; 'key' — ключ не подходит к манифесту. */
async function loadMan(key) {
  let buf;
  try {
    const r = await fetch(new URL('d/m.bin', self.registration.scope), { cache: 'no-cache' });
    if (!r.ok) throw new Error('http');
    buf = await r.arrayBuffer();
  } catch (err) { throw new Error('net'); }
  try { return JSON.parse(new TextDecoder().decode(await dec(key, buf))); } catch (err) { throw new Error('key'); }
}
async function setKey(raw) {
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const man = await loadMan(key);
  KEY = key; MAN = man; MAN_AT = Date.now();
}
/* Перечитать манифест тем же ключом (на сервере могла появиться новая версия книги). Не чаще раза в 10 с. */
function refreshMan() {
  if (!KEY || Date.now() - MAN_AT < 10000) return Promise.resolve(false);
  if (!REFRESH) {
    const key = KEY;
    REFRESH = loadMan(key).then(man => { if (KEY === key) { MAN = man; MAN_AT = Date.now(); } return true; },
      err => { if (err.message === 'key' && KEY === key) { KEY = null; MAN = null; } return false; })
      .finally(() => { REFRESH = null; });
  }
  return REFRESH;
}
self.addEventListener('message', e => {
  const d = e.data || {}, port = e.ports && e.ports[0];
  if (d.type === 'key') {
    e.waitUntil(setKey(d.raw).then(() => port && port.postMessage({ ok: true }),
      err => { port && port.postMessage({ ok: false, why: err && err.message === 'key' ? 'key' : 'net' }); }));
  } else if (d.type === 'lock') { KEY = null; MAN = null; port && port.postMessage({ ok: true }); }
});
function askOne(c) {
  return new Promise(res => {
    const ch = new MessageChannel();
    const done = v => { clearTimeout(t); ch.port1.onmessage = null; ch.port1.close(); res(v); };
    const t = setTimeout(() => done(null), 4000);
    ch.port1.onmessage = ev => done(ev.data && ev.data.raw || null);
    try { c.postMessage({ type: 'need-key' }, [ch.port2]); } catch (err) { done(null); }
  });
}
/* Спрашиваем все вкладки сразу: замороженная или посторонняя вкладка не задерживает остальных. */
async function askClients() {
  const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  if (!list.length) return false;
  return new Promise(resolve => {
    let left = list.length, won = false;
    const fin = () => { if (!won && --left === 0) resolve(false); };
    list.forEach(c => askOne(c).then(async raw => {
      if (!raw || won) return fin();
      try { await setKey(raw); if (!won) { won = true; resolve(true); } }
      catch (err) {
        if (err && err.message === 'key') { try { c.postMessage({ type: 'bad-key' }); } catch (e2) { /* вкладка закрыта */ } }
        fin();
      }
    }));
  });
}
function ensureKey() {
  if (KEY && MAN) return Promise.resolve(true);
  if (!PENDING) PENDING = askClients().finally(() => { PENDING = null; });
  return PENDING;
}
const inject = h => '<meta name="referrer" content="no-referrer"><script>(function(){var H="' + h + '",raw=null;try{raw=sessionStorage.getItem("k")}catch(e){}' +
  'if(!raw){location.replace("../"+location.hash);return}' +
  'var sw=navigator.serviceWorker;if(!sw)return;' +
  'sw.addEventListener("message",function(ev){var d=ev.data||{};' +
  'if(!ev.source||ev.source.scriptURL!==new URL("../sw.js",location.href).href)return;' +
  'if(d.type==="need-key"&&ev.ports&&ev.ports[0]){var b=atob(raw),u=new Uint8Array(b.length);' +
  'for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);ev.ports[0].postMessage({raw:u.buffer})}' +
  'else if(d.type==="bad-key"){try{sessionStorage.removeItem("k")}catch(e){}location.replace("../"+location.hash)}' +
  'else if(d.type==="stale"&&d.h&&d.h!==H){location.reload()}});' +
  'if(sw.startMessages)sw.startMessages()})();<\/script>';

function page(status, text) {
  return new Response('<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="robots" content="noindex"><title>Семейная книга</title></head><body style="background:#14130f;color:#efe9dc;font:17px/1.5 system-ui,sans-serif;padding:24px">' +
    '<p>' + text + '</p><p><a style="color:#d9b36a" href="">Попробовать ещё раз</a> · <a style="color:#d9b36a" href="' + self.registration.scope + 'book/">К началу книги</a></p></body></html>',
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url), scope = new URL(self.registration.scope);
  if (e.request.method !== 'GET' && e.request.method !== 'HEAD') return;
  if (u.origin !== scope.origin || !u.pathname.startsWith(scope.pathname + BOOK)) return;
  e.respondWith(handle(e, u, scope).catch(() => new Response('error', { status: 500 })));
});
/* Достаёт и расшифровывает файл; если его нет под старым именем — перечитывает манифест и пробует ещё раз. */
async function getFile(rel, scope) {
  let status = 404;
  for (let attempt = 0; attempt < 2; attempt++) {
    const key = KEY, m = MAN && Object.prototype.hasOwnProperty.call(MAN, rel) ? MAN[rel] : null;
    if (key && m) {
      let r;
      try { r = await fetch(new URL('d/' + m.f + '.bin', scope)); } catch (err) { return { status: 504 }; }
      if (r.ok) {
        try { return { m, buf: await dec(key, await r.arrayBuffer()) }; } catch (err) { status = 500; }
      } else if (r.status !== 404) return { status: 502 };
    }
    if (attempt || !(await refreshMan())) break;
    status = 404;
  }
  return { status };
}
async function handle(e, u, scope) {
  const req = e.request, nav = req.mode === 'navigate';
  const locked = () => nav ? Response.redirect(scope.href, 302) : new Response('locked', { status: 403 });
  let rel;
  try { rel = decodeURIComponent(u.pathname.slice((scope.pathname + BOOK).length)); } catch (err) { return new Response('bad path', { status: 400 }); }
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  if (!(await ensureKey())) return locked();
  if (nav && rel === 'index.html') await refreshMan();   // при открытии и обновлении страницы — свежая версия книги
  const got = await getFile(rel, scope);
  if (!KEY) return locked();                              // манифест на сервере зашифрован уже другим ключом
  if (!got.buf) {
    if (nav) return page(got.status, got.status === 404 ? 'Такой страницы в книге нет.' : 'Не получилось загрузить книгу. Проверьте соединение с интернетом.');
    if (got.status === 404 && e.clientId && MAN && MAN['index.html']) {   // открытая страница могла устареть
      const c = await self.clients.get(e.clientId);
      if (c) { try { c.postMessage({ type: 'stale', h: MAN['index.html'].h }); } catch (err) { /* вкладка закрыта */ } }
    }
    return new Response('error', { status: got.status });
  }
  const m = got.m; let buf = got.buf;
  if (rel === 'index.html') {
    const html = new TextDecoder().decode(buf), tag = /<head[^>]*>/i.exec(html), ins = inject(m.h);
    buf = new TextEncoder().encode(tag ? html.slice(0, tag.index + tag[0].length) + ins + html.slice(tag.index + tag[0].length) : ins + html).buffer;
  }
  const headers = { 'Content-Type': m.t, 'Cache-Control': 'no-store', 'Accept-Ranges': 'bytes', 'X-Robots-Tag': 'noindex', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };
  const range = req.headers.get('range'), size = buf.byteLength;
  if (range) {
    const mm = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (mm && (mm[1] !== '' || mm[2] !== '')) {
      let start, end;
      if (mm[1] === '') { start = Math.max(0, size - Number(mm[2])); end = size - 1; }
      else { start = Number(mm[1]); end = mm[2] === '' ? size - 1 : Math.min(Number(mm[2]), size - 1); }
      if (start > end || start >= size) return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + size } });
      headers['Content-Range'] = 'bytes ' + start + '-' + end + '/' + size;
      headers['Content-Length'] = String(end - start + 1);
      return new Response(buf.slice(start, end + 1), { status: 206, headers });
    }
  }
  headers['Content-Length'] = String(size);
  return new Response(buf, { status: 200, headers });
}
