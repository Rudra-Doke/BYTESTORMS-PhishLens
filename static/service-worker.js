const CACHE_NAME = "phishlens-shell-v1";
const APP_SHELL = ["/", "/static/style.css", "/static/script.js", "/static/manifest.webmanifest", "/static/phishlens-icon.svg"];

self.addEventListener("install", event => {
    event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)));
    self.skipWaiting();
});

self.addEventListener("activate", event => {
    event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))));
    self.clients.claim();
});

self.addEventListener("fetch", event => {
    const request = event.request;
    const url = new URL(request.url);
    if (request.method !== "GET" || url.origin !== self.location.origin) return;
    if (url.pathname === "/" || url.pathname.startsWith("/static/")) {
        event.respondWith(fetch(request).then(response => {
            if (response.ok) caches.open(CACHE_NAME).then(cache => cache.put(request, response.clone()));
            return response;
        }).catch(async () => (await caches.match(request)) || (await caches.match("/"))));
    }
});
