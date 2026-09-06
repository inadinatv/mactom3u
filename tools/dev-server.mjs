// tools/dev-server.mjs
//
// Yerel geliştirme sunucusu. Vercel'e özel bir şey gerektirmeden
//   npm run dev
// ile projeyi http://localhost:3000 üzerinde çalıştırır.
//
// Üretimde olduğu gibi tek kaynak kullanılır: statik dosyalar kökten servis edilir,
// /api/proxy istekleri doğrudan api/proxy.js içindeki handler'a yönlendirilir.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import handler from '../api/proxy.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

/** Node http isteğini Vercel benzeri { method, body } nesnesine çevirir. */
async function readJsonBody(req, limitBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) throw Object.assign(new Error('Gövde çok büyük'), { status: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  const text = Buffer.concat(chunks).toString('utf8');
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** Vercel `res` nesnesinin kullanılan yüzeyini taklit eder. */
function createResponseAdapter(res) {
  const headers = {};
  let statusCode = 200;
  const api = {
    setHeader(name, value) { headers[name.toLowerCase()] = value; },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    status(code) { statusCode = code; return api; },
    json(payload) {
      headers['content-type'] = 'application/json; charset=utf-8';
      res.writeHead(statusCode, headers);
      res.end(JSON.stringify(payload));
    },
    send(payload) {
      res.writeHead(statusCode, headers);
      res.end(payload);
    },
    end(payload) {
      res.writeHead(statusCode, headers);
      res.end(payload);
    },
  };
  return api;
}

async function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = join(ROOT, normalize(rel));

  // Kök dışına çıkmaya çalışan yolları engelle
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403).end('Forbidden');
    return;
  }

  try {
    const data = await readFile(filePath);
    const type = MIME[extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, {
      'content-type': type,
      'cache-control': 'no-store',
    });
    res.end(data);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('404 — bulunamadı');
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (url.pathname === '/api/proxy') {
    try {
      const body = await readJsonBody(req);
      await handler({ method: req.method, body, headers: req.headers, query: Object.fromEntries(url.searchParams) }, createResponseAdapter(res));
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(err.status || 500, { 'content-type': 'application/json; charset=utf-8' });
      }
      res.end(JSON.stringify({ js: null, error: err.message || 'Sunucu hatası' }));
    }
    return;
  }

  await serveStatic(req, res, url.pathname);
});

server.listen(PORT, HOST, () => {
  console.log(`\n  İnadına TV — Mac to M3U  ·  geliştirme sunucusu`);
  console.log(`  ➜  Yerel:   http://localhost:${PORT}`);
  console.log(`  ➜  Ağ:      http://${HOST === '0.0.0.0' ? '<makine-ip>' : HOST}:${PORT}`);
  console.log(`  ➜  Proxy:   POST /api/proxy  (api/proxy.js)\n`);
});
