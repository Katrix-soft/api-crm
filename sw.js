const CACHE_NAME = 'katrix-panel-cache-v7';
const ASSETS = [
  '/panel',
  '/panel/katrix-biometrics.js',
  '/panel/manifest.json',
  '/panel/icon-192.png',
  '/panel/icon-512.png',
  '/panel/chill_bg.png'
];

// Install Event - Precache Assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Service Worker] Precaching app shell');
      return cache.addAll(ASSETS);
    }).then(() => self.skipWaiting())
  );
});

// Activate Event - Clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[Service Worker] Removing old cache', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch Event - Stale-While-Revalidate Strategy
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Only cache GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  // Do not cache API requests or biometrics to prevent stale data
  if (!url.pathname.startsWith('/panel') || url.pathname.includes('/panel/auth/biometrics/challenge') || url.pathname.includes('/health')) {
    return;
  }

  event.respondWith(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.match(event.request).then((cachedResponse) => {
        const fetchedResponse = fetch(event.request).then((networkResponse) => {
          if (networkResponse.status === 200) {
            cache.put(event.request, networkResponse.clone());
          }
          return networkResponse;
        }).catch((err) => {
          console.log('[Service Worker] Fetch failed, returning cached version if available', err);
        });

        return cachedResponse || fetchedResponse;
      });
    })
  );
});

// Push Event - Web Push API
self.addEventListener('push', (event) => {
  let data = { title: 'Notificación', body: 'Nueva notificación', icon: '/panel/icon-192.png' };
  try {
    if (event.data) {
      data = event.data.json();
    }
  } catch(e) {
    console.warn("Invalid push data");
  }

  const options = {
    body: data.body,
    icon: data.icon || '/panel/icon-192.png',
    badge: '/panel/icon-192.png',
    vibrate: [100, 50, 100],
    data: data.url || '/panel'
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Notification Click Event
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(windowClients => {
      // Check if there is already a window/tab open with the target URL
      for (let i = 0; i < windowClients.length; i++) {
        const client = windowClients[i];
        if (client.url === event.notification.data && 'focus' in client) {
          return client.focus();
        }
      }
      // If not, open a new window
      if (clients.openWindow) {
        return clients.openWindow(event.notification.data);
      }
    })
  );
});
