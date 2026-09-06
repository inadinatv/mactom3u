// api/proxy.js
//
// İnadına TV — Portal Proxy (v2.4.0)
// Tarayıcıdan gelen istekleri IPTV portalına (Stalker / Ministra / MAC-HTTP) iletir,
// dönen JSON veya bozuk XML yanıtını normalize edip frontend'e JSON olarak gönderir.
//
// Bu dosya Vercel / Netlify tarzı "serverless function" imzasını korur:
//   export default async function handler(req, res)

const REQUEST_TIMEOUT_MS = 25000;            // Portal isteği zaman aşımı (vercel.json maxDuration: 30)
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;  // 8 MB — bellek koruması
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

/* ------------------------------------------------------------------ */
/*  Yardımcılar                                                        */
/* ------------------------------------------------------------------ */

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Özel / rezerve IPv4 aralıkları (SSRF koruması + rastgele IP üretimi için ortak)
const PRIVATE_V4_PATTERNS = [
  /^0\./,                                        // 0.0.0.0/8
  /^10\./,                                       // 10.0.0.0/8
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,     // 100.64.0.0/10 (CGNAT)
  /^127\./,                                      // loopback
  /^169\.254\./,                                 // link-local + bulut metadata
  /^172\.(1[6-9]|2\d|3[01])\./,                  // 172.16.0.0/12
  /^192\.0\.0\./, /^192\.0\.2\./, /^192\.168\./,
  /^198\.18\./, /^198\.19\./,                    // benchmark
  /^198\.51\.100\./, /^203\.0\.113\./,           // documentation
  /^(22[4-9]|2[3-5]\d)\./,                       // multicast + rezerve (224-255)
  /^255\./,
];

export function isPrivateIPv4(ip) {
  return PRIVATE_V4_PATTERNS.some((re) => re.test(ip));
}

const BLOCKED_HOSTNAMES = /^(localhost|metadata|metadata\.google\.internal|instance-data|169\.254\.169\.254)$/i;

/**
 * Hedef sunucunun iç ağa / metadata servisine işaret edip etmediğini kontrol eder.
 * Proxy, kullanıcıdan gelen rastgele bir URL'i sunucu adına çektiği için bu şart.
 */
export function isUnsafeHost(hostname) {
  const h = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!h) return true;
  if (BLOCKED_HOSTNAMES.test(h)) return true;
  if (/\.(local|internal|localhost|lan|home|corp)$/i.test(h)) return true;
  // IPv4 literal
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return isPrivateIPv4(h);
  // IPv6 literal — loopback / ULA / link-local
  if (h.includes(':')) return /^(::1|::|f[cd]|fe[89ab])/i.test(h);
  return false;
}

/** Rastgele ama geçerli bir *herkese açık* IPv4 üretir (IP banlanmasına karşı bypass). */
export function generateRandomIP() {
  const rnd = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  for (let i = 0; i < 32; i++) {
    const ip = `${rnd(11, 223)}.${rnd(0, 255)}.${rnd(0, 255)}.${rnd(1, 254)}`;
    if (!isPrivateIPv4(ip)) return ip;
  }
  return '185.22.64.101';
}

/** MAC adresini portalların beklediği biçime (00:1A:79:XX:XX:XX) getirir. */
export function normalizeMac(mac) {
  const raw = String(mac || '').trim();
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (hex.length === 12) return hex.match(/.{2}/g).join(':');
  return raw.toUpperCase(); // Tanımadığımız biçimse dokunmadan geçir
}

/**
 * Portal adresinden hedef load.php URL'ini kurar.
 * Orijinal davranış birebir korunur:
 *   http://site.com        -> http://site.com/c/server/load.php
 *   http://site.com/c/     -> http://site.com/server/load.php
 */
export function buildTargetUrl(portal, params) {
  let raw = String(portal || '').trim();
  if (!raw) return { error: 'Portal adresi boş olamaz.' };

  // http/https dışında bir şema yazılmışsa (ftp://, file:// ...) açıkça reddet.
  // Aksi halde "http://" öneki eklenince ftp://site.com gibi adresler
  // "http://ftp//site.com" biçiminde bozulup sessizce yanlış hedefe gidiyordu.
  const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (schemeMatch && !/^https?$/i.test(schemeMatch[1])) {
    return { error: `Desteklenmeyen protokol: ${schemeMatch[1].toLowerCase()}:// — yalnızca http ve https kullanılabilir.` };
  }

  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;

  let probe;
  try {
    probe = new URL(withScheme);
  } catch {
    return { error: 'Portal adresi geçersiz. Örnek: http://site.com:80 veya http://site.com/c/' };
  }

  if (!/^https?:$/i.test(probe.protocol)) {
    return { error: 'Yalnızca http ve https portalları desteklenir.' };
  }
  if (!probe.hostname || isUnsafeHost(probe.hostname)) {
    return { error: 'Bu portal adresine güvenlik nedeniyle istek atılamaz.' };
  }

  const baseUrl = withScheme.replace(/\/c\/?$/i, '').replace(/\/+$/, '');
  const loadPhpPath = withScheme.includes('/c/') ? '/server/load.php' : '/c/server/load.php';

  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    searchParams.set(key, String(value));
  }
  searchParams.set('JsHttpRequest', '1-xml');

  return { url: `${baseUrl}${loadPhpPath}?${searchParams.toString()}`, baseUrl };
}

/**
 * Portal yanıtını JSON'a çevirir.
 * Stalker portalları bazen saf JSON, bazen <data>{...}</data> XML zarfı,
 * bazen de başına çöp karakter eklenmiş JSON döndürür.
 */
export function parsePortalResponse(text) {
  const data = String(text || '').trim();
  if (!data) return { js: null };

  // 1) Doğrudan JSON
  try {
    return JSON.parse(data);
  } catch {
    /* devam */
  }

  // 2) XML zarfı: <data>{...}</data>
  const xmlMatch = data.match(/<data>([\s\S]*?)<\/data>/i);
  if (xmlMatch) {
    const inner = xmlMatch[1].trim();
    try {
      return JSON.parse(inner);
    } catch {
      /* devam */
    }
    const decoded = inner
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
      .replace(/&amp;/g, '&');
    try {
      return JSON.parse(decoded);
    } catch {
      /* devam */
    }
  }

  // 3) Metin içine gömülü ilk JSON nesnesi
  const braceStart = data.indexOf('{');
  if (braceStart > -1) {
    try {
      return JSON.parse(data.slice(braceStart));
    } catch {
      /* devam */
    }
  }

  return { js: null, raw: data.slice(0, 300) };
}

function fail(res, status, message) {
  return res.status(status).json({ js: null, error: message });
}

/* ------------------------------------------------------------------ */
/*  Handler                                                            */
/* ------------------------------------------------------------------ */

export default async function handler(req, res) {
  // CORS Başlıkları (Farklı yerlerden erişim gerekirse diye)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store');

  // Tarayıcıların ön kontrol (preflight) isteğini yönet
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Sadece POST isteklerini kabul et
  if (req.method !== 'POST') {
    return fail(res, 405, 'Yalnızca POST istekleri kabul edilir.');
  }

  try {
    const body = isObject(req.body) ? req.body : {};
    // Not: body.type (machttp / stalker) yalnızca frontend'de URL üretiminde kullanılır.
    const { portal, mac, token, params } = body;

    if (!portal || !mac) {
      return fail(res, 400, 'Portal ve MAC adresi zorunludur.');
    }
    if (!isObject(params)) {
      return fail(res, 400, 'İstek parametreleri geçersiz.');
    }

    const target = buildTargetUrl(portal, params);
    if (target.error) return fail(res, 400, target.error);
    const { url: targetUrl, baseUrl } = target;

    // Cookie ve Kimlik Doğrulama
    const cleanMac = normalizeMac(mac);
    const cleanToken = typeof token === 'string' ? token.trim() : '';
    let cookie = `mac=${encodeURIComponent(cleanMac)}`;
    if (cleanToken) cookie += `; token=${encodeURIComponent(cleanToken)}`;

    const headers = {
      'User-Agent': USER_AGENT,
      'X-Forwarded-For': generateRandomIP(),
      'Cookie': cookie,
      'Accept': 'application/json, text/plain, */*',
      'Referer': baseUrl,
      'Origin': baseUrl,
      'Content-Type': 'application/json',
    };

    // Ministra/Stalker el sıkışmadan sonra Bearer token bekler; cookie'ye ek olarak gönderilir.
    if (cleanToken && !/^Bearer\s/i.test(cleanToken)) {
      headers['Authorization'] = `Bearer ${cleanToken}`;
    }

    // Karşı sunucuya (IPTV Portalı) isteği at — zaman aşımı korumalı
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let proxyRes;
    try {
      proxyRes = await fetch(targetUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(params),
        signal: controller.signal,
        redirect: 'follow',
      });
    } catch (err) {
      clearTimeout(timer);
      if (err && err.name === 'AbortError') {
        return fail(res, 504, `Portal ${REQUEST_TIMEOUT_MS / 1000} sn içinde yanıt vermedi (zaman aşımı).`);
      }
      return fail(res, 502, 'Portala ulaşılamadı. Adresi ve internet bağlantısını kontrol edin.');
    }
    clearTimeout(timer);

    // Aşırı büyük yanıtlara karşı koruma
    const declaredSize = Number(proxyRes.headers.get('content-length') || 0);
    if (declaredSize > MAX_RESPONSE_BYTES) {
      return fail(res, 413, 'Portal yanıtı çok büyük, işlenemedi.');
    }

    const data = await proxyRes.text();
    if (data.length > MAX_RESPONSE_BYTES) {
      return fail(res, 413, 'Portal yanıtı çok büyük, işlenemedi.');
    }

    // IPTV portalları bazen JSON bazen de bozuk XML döndürür, bunu parse ediyoruz.
    const jsonData = parsePortalResponse(data);

    // Portal hata döndürdüyse frontend'in gösterebileceği bir mesaj ekle
    if (!proxyRes.ok && !jsonData.error) {
      jsonData.error =
        proxyRes.status === 403 ? 'Portal erişimi engelledi (403). MAC/IP banlı olabilir.'
        : proxyRes.status === 404 ? 'Portal adresi yanlış (404). /c/ uzantısını kontrol edin.'
        : `Portal hatası: ${proxyRes.status}`;
    }

    // Elde edilen veriyi arayüze (frontend) yolla
    res.status(proxyRes.status).json(jsonData);
  } catch (err) {
    console.error('Proxy Hatası:', err);
    // Ham hata mesajı istemciye sızdırılmaz (iç ağ bilgisi içerebilir)
    return fail(res, 500, 'Beklenmeyen bir proxy hatası oluştu.');
  }
}
