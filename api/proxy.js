// api/proxy.js

export default async function handler(req, res) {
  // CORS Başlıkları (Farklı yerlerden erişim gerekirse diye)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Tarayıcıların ön kontrol (preflight) isteğini yönet
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Sadece POST isteklerini kabul et
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Yalnızca POST istekleri kabul edilir.' });
  }

  try {
    const { portal, mac, token, type, params } = req.body;

    if (!portal || !mac) {
      return res.status(400).json({ error: 'Portal ve MAC adresi zorunludur.' });
    }

    let baseUrl = portal.replace(/\/c\/?$/, '').replace(/\/$/, '');
    let loadPhpPath = portal.includes('/c/') ? '/server/load.php' : '/c/server/load.php';

    // Stalker portalı için özel parametreler
    const searchParams = new URLSearchParams(params);
    searchParams.set('JsHttpRequest', '1-xml');

    const targetUrl = `${baseUrl}${loadPhpPath}?${searchParams.toString()}`;

    // Cookie ve Kimlik Doğrulama
    let cookie = `mac=${encodeURIComponent(mac)}`;
    if (token) cookie += `; token=${encodeURIComponent(token)}`;

    // Rastgele IP oluşturma (IP banlanmasına karşı bypass)
    function generateRandomIP() {
      return Math.floor(Math.random() * 255) + 1 + '.' + 
             Math.floor(Math.random() * 255) + '.' + 
             Math.floor(Math.random() * 255) + '.' + 
             Math.floor(Math.random() * 255);
    }

    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'X-Forwarded-For': generateRandomIP(),
      'Cookie': cookie,
      'Accept': 'application/json, text/plain, */*',
      'Referer': baseUrl,
      'Content-Type': 'application/json'
    };

    // Karşı sunucuya (IPTV Portalı) isteği at
    const proxyRes = await fetch(targetUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(params),
    });

    const data = await proxyRes.text();
    let jsonData;

    // IPTV portalları bazen JSON bazen de bozuk XML döndürür, bunu parse ediyoruz.
    try {
      jsonData = JSON.parse(data);
    } catch {
      const xmlMatch = data.match(/<data>(.*?)<\/data>/s);
      if (xmlMatch) {
        try { 
          jsonData = JSON.parse(xmlMatch[1]); 
        } catch { 
          jsonData = { js: null }; 
        }
      } else {
        jsonData = { js: null };
      }
    }

    // Elde edilen veriyi arayüze (frontend) yolla
    res.status(proxyRes.status).json(jsonData);

  } catch (err) {
    console.error("Proxy Hatası:", err);
    res.status(500).json({ error: err.message });
  }
}
