// tools/selftest.mjs
//
// Bağımlılıksız öz-test: `npm test`
// Hem api/proxy.js mantığını hem de index.html içindeki saf fonksiyonları doğrular.
// Ağ erişimi gerektirmez (fetch, test sırasında taklit edilir).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';

import handler, {
  buildTargetUrl,
  parsePortalResponse,
  normalizeMac as proxyNormalizeMac,
  generateRandomIP,
  isPrivateIPv4,
  isUnsafeHost,
} from '../api/proxy.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let passed = 0;
let failed = 0;

function check(name, condition, extra = '') {
  if (condition) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    failed++;
    console.log(`  \x1b[31m✗\x1b[0m ${name} ${extra}`);
  }
}

function eq(name, actual, expected) {
  check(name, actual === expected, `(beklenen: ${JSON.stringify(expected)}, gelen: ${JSON.stringify(actual)})`);
}

function group(title) {
  console.log(`\n\x1b[36m${title}\x1b[0m`);
}

/* ------------------------------------------------------------------ */
/*  res / req taklitleri                                               */
/* ------------------------------------------------------------------ */

function mockRes() {
  const state = { status: 200, headers: {}, body: null, ended: false };
  const api = {
    _state: state,
    setHeader(k, v) { state.headers[k.toLowerCase()] = v; },
    status(code) { state.status = code; return api; },
    json(payload) { state.body = payload; state.ended = true; return api; },
    end(payload) { state.body = payload ?? null; state.ended = true; return api; },
  };
  return api;
}

/** globalThis.fetch'i geçici olarak değiştirir. */
function withFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve()
    .then(fn)
    .finally(() => { globalThis.fetch = original; });
}

function fakeResponse({ status = 200, text = '{"js":null}', headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    text: async () => text,
  };
}

/* ------------------------------------------------------------------ */
/*  Testler                                                            */
/* ------------------------------------------------------------------ */

async function run() {
  group('1) Proxy — hedef URL üretimi (orijinal davranış korunmalı)');
  {
    const a = buildTargetUrl('http://sup-4k.org:80', { type: 'stb', action: 'handshake' });
    eq('kök portal -> /c/server/load.php', a.url, 'http://sup-4k.org:80/c/server/load.php?type=stb&action=handshake&JsHttpRequest=1-xml');

    const b = buildTargetUrl('http://sup-4k.org/c/', { type: 'itv' });
    eq('/c/ ile biten portal -> /server/load.php', b.url, 'http://sup-4k.org/server/load.php?type=itv&JsHttpRequest=1-xml');

    const c = buildTargetUrl('http://sup-4k.org/c', { p: 1 });
    eq('/c (eğik çizgisiz) orijinal gibi kalır', c.url, 'http://sup-4k.org/c/server/load.php?p=1&JsHttpRequest=1-xml');

    const d = buildTargetUrl('sup-4k.org', {});
    eq('şemasız adres http:// kabul edilir', d.url, 'http://sup-4k.org/c/server/load.php?JsHttpRequest=1-xml');

    const e = buildTargetUrl('http://sup-4k.org/c/', { rows: 500, fav: 0, boş: undefined });
    check('undefined/null parametreler URL\'e yazılmaz', !e.url.includes('bo'));

    check('geçersiz adres hata döndürür', Boolean(buildTargetUrl('http://', {}).error));
    check('boş adres hata döndürür', Boolean(buildTargetUrl('', {}).error));
    check('params nesne değilse de çalışır', typeof buildTargetUrl('http://a.com', {}).url === 'string');
  }

  group('2) Proxy — SSRF / iç ağ koruması');
  {
    for (const bad of ['http://127.0.0.1', 'http://localhost', 'http://192.168.1.5/c/', 'http://10.0.0.1',
      'http://169.254.169.254', 'http://172.16.0.1', 'http://[::1]', 'ftp://ornek.com']) {
      check(`engellenir: ${bad}`, Boolean(buildTargetUrl(bad, {}).error));
    }
    for (const good of ['http://sup-4k.org', 'https://portal.ornek.com:8080/c/', 'http://51.15.20.30']) {
      check(`izin verilir: ${good}`, Boolean(buildTargetUrl(good, {}).url));
    }
    check('isPrivateIPv4: 10.x özel', isPrivateIPv4('10.1.2.3'));
    check('isPrivateIPv4: 100.64 CGNAT özel', isPrivateIPv4('100.64.0.1'));
    check('isPrivateIPv4: 8.8.8.8 herkese açık', !isPrivateIPv4('8.8.8.8'));
    check('isUnsafeHost: .local engelli', isUnsafeHost('printer.local'));
    check('isUnsafeHost: normal alan adı serbest', !isUnsafeHost('portal.tv'));

    let allPublic = true;
    for (let i = 0; i < 5000; i++) if (isPrivateIPv4(generateRandomIP())) { allPublic = false; break; }
    check('generateRandomIP 5000 denemede hep herkese açık IP üretir', allPublic);
    check('generateRandomIP biçimi geçerli', /^(\d{1,3}\.){3}\d{1,3}$/.test(generateRandomIP()));
  }

  group('3) Proxy — MAC normalleştirme');
  {
    eq('ayraçsız -> iki noktalı', proxyNormalizeMac('001a791b2c3d'), '00:1A:79:1B:2C:3D');
    eq('tireli -> iki noktalı', proxyNormalizeMac('00-1A-79-1B-2C-3D'), '00:1A:79:1B:2C:3D');
    eq('zaten biçimli ise korunur', proxyNormalizeMac('00:1A:79:1B:2C:3D'), '00:1A:79:1B:2C:3D');
    eq('bozuk girdi olduğu gibi geçer', proxyNormalizeMac('abc'), 'ABC');
  }

  group('4) Proxy — yanıt ayrıştırma');
  {
    eq('saf JSON', JSON.stringify(parsePortalResponse('{"js":{"token":"abc"}}')), '{"js":{"token":"abc"}}');
    eq('XML zarfı <data>', JSON.stringify(parsePortalResponse('<data>{"js":42}</data>')), '{"js":42}');
    eq('HTML varlığı içeren XML zarfı', parsePortalResponse('<data>{&quot;js&quot;:1}</data>').js, 1);
    eq('başında çöp olan JSON', parsePortalResponse('OK {"js":7}').js, 7);
    eq('boş yanıt', JSON.stringify(parsePortalResponse('')), '{"js":null}');
    eq('tamamen bozuk yanıt', parsePortalResponse('<html>hata</html>').js, null);
    check('bozuk yanıtta ham metin saklanır', typeof parsePortalResponse('<html>hata</html>').raw === 'string');
  }

  group('5) Proxy — handler uçtan uca (fetch taklidi)');
  {
    let res = mockRes();
    await handler({ method: 'OPTIONS', body: {} }, res);
    eq('OPTIONS -> 200', res._state.status, 200);
    eq('CORS başlığı var', res._state.headers['access-control-allow-origin'], '*');
    eq('no-store var', res._state.headers['cache-control'], 'no-store');

    res = mockRes();
    await handler({ method: 'GET', body: {} }, res);
    eq('GET -> 405', res._state.status, 405);

    res = mockRes();
    await handler({ method: 'POST', body: {} }, res);
    eq('eksik alan -> 400', res._state.status, 400);

    res = mockRes();
    await handler({ method: 'POST', body: { portal: 'http://a.com', mac: '00:1A:79:00:00:01', params: 'bozuk' } }, res);
    eq('params nesne değil -> 400', res._state.status, 400);

    // İç ağa istek atılmamalı (fetch hiç çağrılmamalı)
    let fetchCalled = false;
    res = mockRes();
    await withFetch(async () => { fetchCalled = true; return fakeResponse(); }, () =>
      handler({ method: 'POST', body: { portal: 'http://169.254.169.254', mac: '00:1A:79:00:00:01', params: { type: 'stb' } } }, res));
    eq('metadata adresi -> 400', res._state.status, 400);
    check('metadata adresinde fetch hiç çağrılmadı', !fetchCalled);

    // Başarılı istek: başlıklar ve URL doğrulanır
    let captured = null;
    res = mockRes();
    await withFetch(async (url, opts) => { captured = { url, opts }; return fakeResponse({ text: '{"js":{"token":"T0KEN"}}' }); }, () =>
      handler({
        method: 'POST',
        body: { portal: 'http://sup-4k.org:80', mac: '001a79000001', token: 'T0KEN', type: 'stalker', params: { type: 'itv', action: 'get_genres' } },
      }, res));
    eq('başarılı istek -> 200', res._state.status, 200);
    eq('token yanıtı aynen iletilir', res._state.body.js.token, 'T0KEN');
    check('doğru URL\'e istek atıldı', captured.url.startsWith('http://sup-4k.org:80/c/server/load.php?'), captured?.url);
    eq('cookie MAC normalleştirilmiş', captured.opts.headers.Cookie, 'mac=00%3A1A%3A79%3A00%3A00%3A01; token=T0KEN');
    eq('Bearer token eklendi', captured.opts.headers.Authorization, 'Bearer T0KEN');
    eq('Referer portal kökü', captured.opts.headers.Referer, 'http://sup-4k.org:80');
    check('X-Forwarded-For dolu', /^\d+\.\d+\.\d+\.\d+$/.test(captured.opts.headers['X-Forwarded-For']));
    eq('gövde params olarak gönderildi', captured.opts.body, JSON.stringify({ type: 'itv', action: 'get_genres' }));

    // Portal 403 dönerse
    res = mockRes();
    await withFetch(async () => fakeResponse({ status: 403, text: '<html>Forbidden</html>' }), () =>
      handler({ method: 'POST', body: { portal: 'http://sup-4k.org', mac: '00:1A:79:00:00:01', params: { type: 'stb' } } }, res));
    eq('portal 403 -> 403', res._state.status, 403);
    check('403 için anlaşılır mesaj', /403/.test(res._state.body.error || ''), JSON.stringify(res._state.body));

    // Zaman aşımı
    res = mockRes();
    await withFetch(async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; }, () =>
      handler({ method: 'POST', body: { portal: 'http://sup-4k.org', mac: '00:1A:79:00:00:01', params: { type: 'stb' } } }, res));
    eq('zaman aşımı -> 504', res._state.status, 504);

    // Ağ hatası
    res = mockRes();
    await withFetch(async () => { throw new TypeError('fetch failed'); }, () =>
      handler({ method: 'POST', body: { portal: 'http://sup-4k.org', mac: '00:1A:79:00:00:01', params: { type: 'stb' } } }, res));
    eq('ulaşılamayan portal -> 502', res._state.status, 502);

    // Aşırı büyük yanıt
    res = mockRes();
    await withFetch(async () => fakeResponse({ headers: { 'content-length': String(20 * 1024 * 1024) } }), () =>
      handler({ method: 'POST', body: { portal: 'http://sup-4k.org', mac: '00:1A:79:00:00:01', params: { type: 'stb' } } }, res));
    eq('dev yanıt -> 413', res._state.status, 413);

    // Beklenmeyen hata: iç ayrıntı sızmamalı
    res = mockRes();
    await handler({ method: 'POST', get body() { throw new Error('iç hata detayı'); } }, res);
    eq('beklenmeyen hata -> 500', res._state.status, 500);
    check('ham hata mesajı istemciye sızmıyor', !/iç hata detayı/.test(res._state.body.error || ''));
  }

  group('6) Frontend — index.html saf fonksiyonları');
  {
    const html = readFileSync(resolve(ROOT, 'index.html'), 'utf8');
    const match = html.match(/<script>([\s\S]*?)<\/script>/);
    check('index.html içinde <script> bloğu bulundu', Boolean(match));

    const source = `${match[1]}\n;globalThis.__x = { esc, m3uAttr, normalizeMac, isValidMac, normalizePortal, getDefaultFilename, formatBytes, APP_VERSION };`;

    const noop = () => {};
    const sandbox = {
      console,
      URL,
      Blob: class { constructor(parts) { this.size = parts.join('').length; } },
      DOMException: class extends Error { constructor(m, n) { super(m); this.name = n; } },
      navigator: {},
      localStorage: { getItem: noop, setItem: noop, removeItem: noop },
      document: { getElementById: () => null, addEventListener: noop, querySelectorAll: () => [] },
      window: { addEventListener: noop, isSecureContext: true },
      setTimeout, clearTimeout,
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox);
    const x = sandbox.__x;

    eq('sürüm etiketi', x.APP_VERSION, '2.4.0');
    eq('esc() HTML kaçışlar', x.esc('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
    eq('esc() tırnak kaçışlar', x.esc('"\'&'), '&quot;&#39;&amp;');
    eq('esc() null güvenli', x.esc(null), '');
    eq('m3uAttr() tırnağı temizler', x.m3uAttr('Kanal "HD"'), "Kanal 'HD'");
    eq('m3uAttr() satır sonunu temizler', x.m3uAttr('a\r\nb'), 'a b');
    eq('normalizeMac() biçimlendirir', x.normalizeMac('001a791b2c3d'), '00:1A:79:1B:2C:3D');
    check('isValidMac() geçerli', x.isValidMac('00:1A:79:1B:2C:3D'));
    check('isValidMac() eksik reddeder', !x.isValidMac('00:1A:79'));
    check('isValidMac() harf dışı reddeder', !x.isValidMac('00:1A:79:1B:2C:ZZ'));
    eq('normalizePortal() şema ekler', x.normalizePortal('sup-4k.org'), 'http://sup-4k.org');
    eq('normalizePortal() https korur', x.normalizePortal('https://a.com/c/'), 'https://a.com/c/');
    eq('normalizePortal() ftp reddeder', x.normalizePortal('ftp://a.com'), null);
    eq('normalizePortal() localhost reddeder', x.normalizePortal('localhost'), null);
    eq('normalizePortal() boş reddeder', x.normalizePortal('   '), null);
    check('getDefaultFilename() biçimi', /^INADINATV_MAC_\d{2}_\d{2}_\d{4}$/.test(x.getDefaultFilename()));
    eq('formatBytes() B', x.formatBytes(512), '512 B');
    eq('formatBytes() KB', x.formatBytes(2048), '2.0 KB');
    eq('formatBytes() MB', x.formatBytes(3 * 1024 * 1024), '3.00 MB');
  }

  group('7) Frontend — statik bütünlük');
  {
    const html = readFileSync(resolve(ROOT, 'index.html'), 'utf8');
    const ids = ['type', 'stream-ext', 'portal', 'mac', 'btn-connect', 'btn-loader', 'status', 'progress-wrap',
      'progress-bar', 'progress-text', 'btn-stop-scan', 'category-modal', 'modal-subtitle', 'search-categories',
      'modal-warning', 'check-all', 'check-all-visual', 'selected-count', 'category-list', 'category-empty',
      'footer-sel-num', 'btn-download', 'btn-download-text', 'download-loader', 'save-modal', 'final-filename',
      'save-channel-count', 'save-file-size', 'save-group-count', 'btn-copy', 'portal-hint', 'mac-hint'];
    const missing = ids.filter((id) => !html.includes(`id="${id}"`));
    check('JS\'in kullandığı tüm id\'ler HTML\'de mevcut', missing.length === 0, `eksik: ${missing.join(', ')}`);

    const fns = ['baglanVeKategorileriGetir', 'kapatModal', 'toggleAllCustom', 'indirmeyiBaslat', 'kapatSaveModal',
      'gercekIndirmeyiTetikle', 'taramayiDurdur', 'm3uKopyala'];
    const missingFn = fns.filter((f) => !new RegExp(`function ${f}\\b`).test(html));
    check('HTML\'den çağrılan tüm fonksiyonlar tanımlı', missingFn.length === 0, `eksik: ${missingFn.join(', ')}`);

    check('portal verisi innerHTML\'e kaçışlanarak yazılıyor', html.includes('${esc(title)}') && html.includes('${esc(g.id)}'));
    check('arama dinleyicisi bir kez bağlanıyor', html.includes('if (searchBound) return;'));
    check('"Tümünü Seç" çift tetikleme düzeltmesi var', html.includes('onclick="toggleAllCustom(event)"') && /e\.preventDefault\(\)/.test(html));
    check('alert() kaldırıldı', !/[^.\w]alert\(/.test(html));
    check('blob URL geri bırakılıyor', html.includes('URL.revokeObjectURL'));
    check('noscript uyarısı var', html.includes('<noscript>'));
    check('prefers-reduced-motion desteği', html.includes('prefers-reduced-motion'));
  }

  group('8) Frontend — uçtan uca tarama + M3U üretimi (sahte DOM)');
  {
    const html = readFileSync(resolve(ROOT, 'index.html'), 'utf8');
    const source = `${html.match(/<script>([\s\S]*?)<\/script>/)[1]}
;globalThis.__x = {
  baglanVeKategorileriGetir, indirmeyiBaslat, renderModal,
  get m3u() { return generatedM3uContent; },
  get stats() { return generatedStats; },
  get token() { return apiToken; },
  get katMap() { return katMap; },
};`;

    /* --- Mini DOM taklidi --- */
    function makeEl(id = '') {
      const el = {
        id, value: '', textContent: '', className: '', disabled: false,
        style: {}, dataset: {}, innerHTML: '', children: [], lastChild: { textContent: '' },
        classList: {
          _s: new Set(),
          add(c) { this._s.add(c); },
          remove(c) { this._s.delete(c); },
          contains(c) { return this._s.has(c); },
          toggle(c, force) {
            const on = force === undefined ? !this._s.has(c) : Boolean(force);
            on ? this._s.add(c) : this._s.delete(c);
            return on;
          },
        },
        addEventListener() {}, removeEventListener() {}, appendChild(c) { this.children.push(c); return c; },
        querySelector() { return makeEl(); }, querySelectorAll() { return []; },
        closest() { return null; }, focus() {}, select() {}, click() {},
      };
      return el;
    }

    const elements = {};
    const el = (id) => (elements[id] ||= makeEl(id));
    // Taranacak kategoriler: 1 = Ulusal, 2 = Spor
    const selectedBoxes = [{ value: '1' }, { value: '2' }];

    const documentStub = {
      getElementById: (id) => el(id),
      querySelectorAll: (sel) => (sel === '.cat-checkbox:checked' ? selectedBoxes : []),
      createElement: () => makeEl(),
      createDocumentFragment: () => makeEl(),
      addEventListener() {},
      body: makeEl('body'),
    };

    el('portal').value = 'sup-4k.org';       // şemasız — otomatik http:// eklenmeli
    el('mac').value = '001a79112233';        // iki noktasız — otomatik biçimlendirilmeli
    el('type').value = 'machttp';
    el('stream-ext').value = 'ts';

    /* --- Portal taklidi --- */
    const calls = [];
    const channels = {
      '1': [
        { id: 101, name: 'Kanal "Bir"', cmd: 'ffmpeg http://x/ch/101', number: 2, logo: 'http://l/1.png', xmltv_id: 'bir.tv', tv_genre_id: 1 },
        { id: 102, name: 'Kanal İki', cmd: 'ffmpeg http://x/ch/102', number: 1, logo: '', xmltv_id: '', tv_genre_id: 1 },
      ],
      // 2. kategori iki sayfaya bölünmüş ve 2. sayfada bir tekrar var
      '2:p1': [{ id: 201, name: 'Spor HD', cmd: 'http://x/201', number: 1, tv_genre_id: 2 }],
      '2:p2': [
        { id: 201, name: 'Spor HD', cmd: 'http://x/201', number: 1, tv_genre_id: 2 }, // tekrar — elenmeli
        { id: 202, name: 'Spor 2', cmd: 'ffmpeg http://x/ch/202', number: 5, tv_genre_id: 2 },
      ],
    };

    const mockFetch = async (url, opts) => {
      const sent = JSON.parse(opts.body);
      calls.push({ url, sent, signal: opts.signal });
      const p = sent.params || {};
      let payload;
      if (p.action === 'handshake') payload = { js: { token: 'TOK123', random: 'x' } };
      else if (p.action === 'get_genres') payload = { js: [{ id: 1, title: 'Ulusal' }, { id: 2, title: 'Spor' }] };
      else if (p.action === 'get_ordered_list') {
        const key = `${p.genre}:p${p.p}`;
        const data = channels[key] || channels[String(p.genre)] || [];
        const total = p.genre === '2' || p.genre === 2 ? 3 : 2;
        payload = { js: { data, total_items: total, selected_item: 0 } };
      } else payload = { js: null };
      return {
        ok: true, status: 200,
        headers: { get: () => null },
        json: async () => payload,
      };
    };

    const sandbox = {
      console, URL, AbortController, DOMException: class extends Error { constructor(m, n) { super(m); this.name = n; } },
      Blob: class { constructor(parts) { this.size = parts.join('').length; } },
      navigator: {}, setTimeout, clearTimeout, setInterval, clearInterval,
      localStorage: { _d: {}, getItem(k) { return this._d[k] ?? null; }, setItem(k, v) { this._d[k] = String(v); }, removeItem(k) { delete this._d[k]; } },
      document: documentStub,
      window: { addEventListener() {}, isSecureContext: true },
      fetch: mockFetch,
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox);
    const x = sandbox.__x;

    // 1. adım: handshake + kategoriler
    await x.baglanVeKategorileriGetir();
    eq('handshake tokenı saklandı', x.token, 'TOK123');
    eq('kategori haritası kuruldu', Object.keys(x.katMap).length, 2);
    eq('şemasız portal http:// ile tamamlandı', el('portal').value, 'http://sup-4k.org');
    eq('iki noktasız MAC biçimlendirildi', el('mac').value, '00:1A:79:11:22:33');
    check('kategori modalı açıldı', el('category-modal').classList.contains('open'));
    check('başarı durumu gösterildi', el('status').className === 'success', el('status').className);

    // 2. adım: kanalları tara ve M3U üret
    await x.indirmeyiBaslat();
    const m3u = x.m3u;

    check('M3U başlığı doğru', m3u.startsWith('#EXTM3U\n'), JSON.stringify(m3u.slice(0, 20)));
    eq('tekrarlar elendi, 4 kanal yazıldı', x.stats.channels, 4);
    eq('grup sayısı', x.stats.groups, 2);
    eq('EXTINF satır sayısı', (m3u.match(/#EXTINF/g) || []).length, 4);
    eq('sayfalama yapıldı (2. kategori 2 sayfa)', calls.filter((c) => c.sent.params?.action === 'get_ordered_list').length, 3);

    // machttp URL biçimi + MAC kodlaması
    check(
      'machttp linki doğru kuruldu',
      m3u.includes('http://sup-4k.org/play/live.php?mac=00%3A1A%3A79%3A11%3A22%3A33&stream=101&extension=ts'),
      m3u.slice(0, 400)
    );
    // Kanal adı içindeki tırnak M3U'yu bozmamalı
    check('tırnaklı kanal adı temizlendi', m3u.includes('tvg-name="Kanal \'Bir\'"') && !m3u.includes('tvg-name="Kanal "Bir""'));
    check('EPG ve logo öznitelikleri yazıldı', m3u.includes('tvg-id="bir.tv"') && m3u.includes('tvg-logo="http://l/1.png"'));
    check('grup başlığı kategori adından geldi', m3u.includes('group-title="Ulusal"') && m3u.includes('group-title="Spor"'));
    // Sıralama: seçilen kategori sırası, sonra kanal numarası
    const order = [...m3u.matchAll(/group-title="([^"]+)",(.+?)\n/g)].map((m) => `${m[1]}/${m[2]}`);
    eq('sıralama doğru', order.join(' | '), 'Ulusal/Kanal İki | Ulusal/Kanal \'Bir\' | Spor/Spor HD | Spor/Spor 2');
    check('kayıt modalı açıldı', el('save-modal').classList.contains('open'));
    check('dosya adı önerisi dolduruldu', /^INADINATV_MAC_/.test(el('final-filename').value));
    eq('kanal sayısı etikete yazıldı', el('save-channel-count').textContent, 4);
    check('ilerleme %100 yapıldı', el('progress-bar').style.width === '100%', el('progress-bar').style.width);
    check('istemciye giden istekte Bearer token var', calls.some((c) => c.sent.token === 'TOK123'));
    check('tarama istekleri iptal edilebilir sinyalle atıldı',
      calls.filter((c) => c.sent.params?.action === 'get_ordered_list').every((c) => c.signal instanceof AbortSignal));

    // 3. adım: stalker tipi URL biçimi
    el('type').value = 'stalker';
    await x.indirmeyiBaslat();
    check('stalker linki /c/ch/ biçiminde', x.m3u.includes('http://sup-4k.org/c/ch/101'), x.m3u.slice(0, 300));
    eq('stalker modunda da 4 kanal', x.stats.channels, 4);

    // 4. adım: m3u8 uzantısı seçimi
    el('type').value = 'machttp';
    el('stream-ext').value = 'm3u8';
    await x.indirmeyiBaslat();
    check('m3u8 uzantısı linke yansıdı', x.m3u.includes('&extension=m3u8'));

    // 5. adım: kategori seçilmediyse uyarı (alert yerine modal içi mesaj)
    selectedBoxes.length = 0;
    await x.indirmeyiBaslat();
    check('seçim yoksa modal uyarısı gösterildi', el('modal-warning').classList.contains('visible'));

    // 6. adım: portal hata verirse kullanıcıya anlaşılır mesaj
    selectedBoxes.push({ value: '1' });
    sandbox.fetch = async () => ({ ok: false, status: 403, headers: { get: () => null }, json: async () => ({ js: null, error: 'Portal erişimi engelledi (403).' }) });
    await x.baglanVeKategorileriGetir();
    check('403 hatası durum çubuğuna yansıdı', /403/.test(el('status').textContent), el('status').textContent);
  }

  console.log(`\n${'─'.repeat(52)}`);
  if (failed === 0) {
    console.log(`\x1b[32m  BAŞARILI — ${passed} test geçti\x1b[0m\n`);
    process.exit(0);
  }
  console.log(`\x1b[31m  ${failed} test BAŞARISIZ\x1b[0m, ${passed} geçti\n`);
  process.exit(1);
}

run().catch((err) => {
  console.error('Test koşucusu patladı:', err);
  process.exit(1);
});
