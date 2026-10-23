// Shared by the dashboard (index.html) and the field app (/mobile).
// Network-first for same-origin pages and assets, so a deploy shows up on
// the next load; the cached copy is only used when the network fails.
// /api/ calls and cross-origin requests are never intercepted.
const CACHE_NAME = 'cams-v2';
const ASSETS = [
  '/',
  '/index.html',
  '/mobile',
  '/field-app.html',
  '/field-manifest.json',
  '/logo.png',
  '/logo-light.png',
  '/favicon.png',
  '/192.png',
  '/particles.js',
  '/tabler-icons.min.css',
  '/tabler-icons.woff2',
  '/tabler-icons.woff'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok && response.type === 'basic') {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request, { ignoreSearch: url.pathname.startsWith('/tabler-icons') })
        .then((cached) => cached || (request.mode === 'navigate'
          ? caches.match(url.pathname.startsWith('/mobile') ? '/mobile' : '/')
          : undefined))
        .then((cached) => cached || Response.error()))
  );
});
