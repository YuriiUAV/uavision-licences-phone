// Service worker: so guarda os ficheiros da PROPRIA pagina (para abrir mais depressa e mostrar o ecra sem rede).
// Rede primeiro (uma versao nova publicada entra logo); a cache so serve se nao houver rede.
// Nunca toca nos pedidos ao servidor Supabase (outra origem) nem guarda dados.
const CACHE = 'uavision-licencas-1.0.7';
const FILES = ['./', 'index.html', 'app.css', 'app.js', 'core.js', 'vendor/noble-ed25519-2.3.0.js', 'manifest.webmanifest', 'icon-180.png', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png', 'logo.png'];

self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin) return;   // o servidor e o resto: direto, sem cache
  e.respondWith(fetch(e.request).then((r) => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true })));
});
