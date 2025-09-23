# Laravel Integration Guide

This guide walks through connecting a Laravel application to the Nucleus Proxy so that your backend can issue scoped JWTs and your Livewire + Tailwind UI can reuse the proxy console experience and uploader components.

## 1. Prerequisites

- Laravel 10+ with PHP 8.2+
- Composer dependencies installed (`laravel/sanctum` recommended if you expose tokens to browsers)
- Node + Vite toolchain (Laravel Breeze, Jetstream, or custom setup)
- Access to the proxy deployment URL and valid Omniverse credentials that the proxy can use for upstream auth

> **Terminology**
>
> - **Proxy base URL** – Public endpoint where this service is deployed (e.g. `https://proxy.example.com`).
> - **Omniverse username/password** – Credentials the proxy uses to authenticate with Nucleus.
> - **Scoped JWT** – Short-lived JWT containing path-based permissions (read/write) that end users present to the proxy.

## 2. Environment Configuration

Add the proxy details and Omniverse credentials to your Laravel `.env` file. All values are required; adjust names to fit your secrets manager.

```env
NUCLEUS_PROXY_URL=https://proxy.example.com
NUCLEUS_PROXY_USERNAME=omniverse
NUCLEUS_PROXY_PASSWORD=super-secret
NUCLEUS_PROXY_TIMEOUT=10
NUCLEUS_PROXY_DEFAULT_SCOPE=/tenants/acme
```

Create corresponding entries inside `config/services.php`:

```php
// config/services.php
return [
    // ...
    'nucleus_proxy' => [
        'base_url'   => env('NUCLEUS_PROXY_URL'),
        'username'   => env('NUCLEUS_PROXY_USERNAME'),
        'password'   => env('NUCLEUS_PROXY_PASSWORD'),
        'timeout'    => env('NUCLEUS_PROXY_TIMEOUT', 15),
        'default_scope' => env('NUCLEUS_PROXY_DEFAULT_SCOPE', '/'),
    ],
];
```

## 3. Service: Authenticating With The Proxy

Create a service that logs the Laravel backend into the proxy and caches the resulting JWT. This token carries the `issue-tokens` ability and is required to mint scoped JWTs for end users.

```php
<?php

namespace App\Services\Nucleus;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class ProxyAuthenticator
{
    private string $baseUrl;
    private string $username;
    private string $password;
    private int $timeout;

    public function __construct()
    {
        $config = config('services.nucleus_proxy');
        $this->baseUrl  = rtrim($config['base_url'], '/');
        $this->username = $config['username'];
        $this->password = $config['password'];
        $this->timeout  = (int) $config['timeout'];
    }

    public function token(): string
    {
        return Cache::remember('nucleus-proxy-admin-token', now()->addMinutes(10), function () {
            $response = Http::timeout($this->timeout)->post("{$this->baseUrl}/v1/auth/login", [
                'username' => $this->username,
                'password' => $this->password,
            ]);

            $response->throw();
            return $response->json('access_token');
        });
    }
}
```

## 4. Service: Issuing Scoped Access Tokens

The service below calls `/v1/auth/token` to create a short-lived scoped token limited to a directory (folder). You can extend it to include additional metadata or abilities.

```php
<?php

namespace App\Services\Nucleus;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class ScopedTokenFactory
{
    public function __construct(private ProxyAuthenticator $authenticator) {}

    public function issue(string $subject, string $path, array $permissions = ['read', 'write'], int $ttlMinutes = 30): array
    {
        $baseUrl = rtrim(config('services.nucleus_proxy.base_url'), '/');

        $response = Http::withToken($this->authenticator->token())
            ->post("{$baseUrl}/v1/auth/token", [
                'subject' => $subject,
                'expires_in_minutes' => $ttlMinutes,
                'scopes' => [[
                    'path' => $path,
                    'permissions' => $permissions,
                ]],
                'metadata' => [
                    'issued_by_app' => config('app.name'),
                    'one_time_use' => false,
                ],
            ]);

        $response->throw();
        return $response->json();
    }
}
```

Typical usage inside a controller:

```php
public function createUploadToken(Request $request, ScopedTokenFactory $tokens)
{
    $user = $request->user();
    $directory = sprintf('/tenants/%s/users/%s', $user->tenant_id, $user->id);

    $result = $tokens->issue(
        subject: $user->id,
        path: $directory,
        permissions: ['read', 'write'],
        ttlMinutes: 15,
    );

    return response()->json($result);
}
```

## 5. Passing Tokens to Livewire Components

You can expose the scoped token to the browser via:

1. A dedicated endpoint returning the token JSON.
2. A Livewire action that calls the factory and stores the token in component state.
3. An Inertia/Blade view that receives the token server-side.

Example Livewire component that obtains a token and makes it available to the frontend console:

```php
<?php

namespace App\Http\Livewire\Storage;

use Livewire\Component;
use App\Services\Nucleus\ScopedTokenFactory;

class FileExplorer extends Component
{
    public string $token = '';

    public function mount(ScopedTokenFactory $factory)
    {
        $user = auth()->user();
        $scopePath = sprintf('/tenants/%s/users/%s', $user->tenant_id, $user->id);
        $result = $factory->issue($user->id, $scopePath);
        $this->token = $result['access_token'];
    }

    public function render()
    {
        return view('livewire.storage.file-explorer');
    }
}
```

And the Blade template (`resources/views/livewire/storage/file-explorer.blade.php`):

```blade
<div x-data="nucleusConsole({
        baseUrl: '{{ rtrim(config('services.nucleus_proxy.base_url'), '/') }}',
        token: @js($token),
        selectors: {
            dropzone: '#proxy-dropzone',
            fileTableBody: '#proxy-file-table-body',
            statusBanner: '#proxy-status-banner',
        },
    })" x-init="init()" class="space-y-6">
    <div id="proxy-status-banner" class="hidden rounded-md border px-4 py-3 text-sm"></div>

    <div class="rounded-xl border border-slate-800 bg-slate-900">
        <table class="min-w-full divide-y divide-slate-800 text-sm">
            <tbody id="proxy-file-table-body" class="divide-y divide-slate-800"></tbody>
        </table>
    </div>

    <div id="proxy-dropzone" class="rounded-xl border-2 border-dashed border-slate-700 bg-slate-900 px-6 py-12 text-center">
        <p class="text-lg font-semibold">Drop files here</p>
        <p class="text-sm text-slate-400">or click to browse</p>
        <input type="file" class="hidden" multiple />
    </div>
</div>
```

## 6. Reusing the Frontend Scripts

Two JS files ship with the proxy:

- `app/static/js/nucleus-proxy-client.js` – small client wrapper around the REST API.
- `app/static/js/nucleus-proxy-console.js` – UI controller that powers the dashboard and uploader.

### 6.1. Bundling with Vite

Copy the scripts into your Laravel `resources/js` folder (or import them directly if you prefer using npm via a private package). Then, in `resources/js/nucleus/index.js`:

```js
import './nucleus-proxy-client'
import './nucleus-proxy-console'

document.addEventListener('alpine:init', () => {
    window.nucleusConsole = (options = {}) => {
        const instance = new window.NucleusProxyConsole({
            baseUrl: options.baseUrl || '',
            client: new window.NucleusProxyClient({ baseUrl: options.baseUrl || '' }),
            selectors: options.selectors,
        })
        return {
            init() {
                if (options.token) {
                    instance.client.setToken(options.token)
                }
                instance.init()
            },
        }
    }
})
```

Register the entrypoint with Vite:

```js
// vite.config.js
export default defineConfig({
  // ...
  build: {
    rollupOptions: {
      input: {
        app: 'resources/js/app.js',
        nucleus: 'resources/js/nucleus/index.js',
      },
    },
  },
})
```

Compile assets with `npm run build` (or `npm run dev`). The resulting bundle exposes `window.NucleusProxyConsole` and `window.nucleusConsole` for your Livewire/Alpine components.

### 6.2. Tailwind Customization

The console script uses utility classes for state (badges, tables, controls). Override them with Tailwind by extending component markup or injecting theme tokens via data attributes:

```css
/* resources/css/app.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

.proxy-badge {
  @apply inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium;
}
```

Use `syncBadgeFormatter` (override `_getSyncDisplay`) to inject icons or change colors:

```js
const consoleInstance = new window.NucleusProxyConsole({
  baseUrl: '/proxy',
  client: new window.NucleusProxyClient({ baseUrl: '/proxy' }),
  selectors: {...},
})

consoleInstance._getSyncDisplay = (entry) => {
  const info = window.NucleusProxyConsole.prototype._getSyncDisplay.call(consoleInstance, entry)
  if (info) {
    info.variant = 'bg-emerald-500/10 text-emerald-200 border border-emerald-600/50'
  }
  return info
}
```

## 7. Wiring Livewire Actions

If you prefer retrieving tokens lazily (e.g. when a user clicks an upload button), expose a Livewire `generateToken` action that hits a Laravel API route returning the JSON, then call `instance.client.setToken(newToken)`.

```php
public function generateToken(): void
{
    $user = auth()->user();
    $scope = sprintf('/projects/%s', $user->active_project_id);
    $result = app(ScopedTokenFactory::class)->issue($user->id, $scope);

    $this->dispatchBrowserEvent('nucleus-token-issued', [
        'token' => $result['access_token'],
    ]);
}
```

Then listen in Alpine:

```js
window.addEventListener('nucleus-token-issued', (event) => {
  consoleInstance.client.setToken(event.detail.token)
})
```

## 8. Testing

Automate integration checks by hitting your Laravel endpoint that issues scoped tokens and verifying:

1. The HTTP status is successful.
2. The token decodes correctly and contains the expected `scopes` array.
3. The token works against `/v1/files/list` for the granted path but fails for unrelated paths.

Use PHPUnit or Pest to stub the proxy using Laravel’s HTTP fakes:

```php
Http::fake([
    '*/v1/auth/token' => Http::response([
        'access_token' => 'fake',
        'scopes' => [['path' => '/projects/demo', 'permissions' => ['read']]],
    ], 201),
]);
```

## 9. Production Hardening Checklist

- Rotate the admin login/token frequently (consider using env overrides per environment).
- Store Omniverse credentials in a vault (e.g. AWS Secrets Manager) and load them at runtime.
- Use HTTPS between Laravel and the proxy; configure CSRF/authorization around routes that issue new tokens.
- Limit token lifetime (e.g. 15 minutes) and reissue when needed.
- Monitor proxy logs for 403 responses to detect scope misconfiguration.

---

With these pieces, Laravel can mint scope-aware JWTs, pass them to Livewire components, and reuse the proxy’s frontend logic with minimal duplication.
