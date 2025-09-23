# NVIDIA Omniverse Nucleus – Practical Protocol Notes (Observed)

This document summarizes what we validated against your Nucleus server and what the shipped web bundle suggests about the protocol: transports, services, methods, payload shapes, and behaviors. It is intended as an engineering aide, not an official spec.

The examples below are the exact shapes we used successfully from `main.py` and by probing the server. Some capabilities exist in the bundle but were not fully exercised; those are marked accordingly.

## Architecture & Ports

- 3333 – Discovery (`DiscoverySearch.*`, WebSocket SOWS binary envelope)
- 3100 – Authentication (`Credentials.*`, WebSocket SOWS binary envelope)
- 3009 – Core Filesystem API (WebSocket JSON frames; streaming for some commands)
- 3400 – Search (`Search.*`, WebSocket SOWS binary envelope)
- 3020 – Tagging (`TaggingService.*`, WebSocket SOWS binary envelope)
- 3030 – Large File Transfer (HTTP upload/download helpers)
- 8080 – Web UI (useful as Origin for WS; bundle hints and static assets)

Terminology in bundle: “SOWS” transport with `marshaller: bs` and `serializer: json` for service calls; core API uses JSON text frames (no binary envelope).

## Transports

### SOWS binary envelope (Discovery, Credentials, Search, Tagging)

For these services, each WebSocket message is a binary frame with:

1. 5‑byte header: `01 01 00 00 00`
2. Method string (UTF‑8) + `00` terminator
3. 4‑byte little‑endian payload length
4. Payload: JSON UTF‑8 (object)

Response frames are also binary; they often include a JSON payload that can be located by scanning for the first `{` byte and decoding to UTF‑8 JSON.

### Core API WebSocket (port 3009, JSON text)

Core filesystem commands are plain JSON text frames (no binary envelope). Many commands use an `id` field and respond either once or as a stream of partial responses capped with a final status.

## Authentication Flow

1. Credentials service (port 3100):
   - Method: `Credentials.auth`
   - Payload (JSON inside SOWS envelope):
     - `version: 1`
     - `username: string`
     - `password: string`
   - Response: `{ status: "OK", access_token: string, ... }` on success
   - We reuse the `access_token` for all subsequent services.

2. Authorize core API connection (port 3009):
   - Command: `authorize_token` (JSON text frame)
   - Payload:
     - `token: string` (the access token from Credentials.auth)
     - `version: string` (observed: `"1.19"`)
     - `client_capabilities: { ... }` (see Capabilities below)
     - `id: number` (request id)
     - `command: "authorize_token"`
   - Success response example includes:
     - `status: "OK"`
     - `connection_id: string`
     - `token: string` (connection token)
     - `lft_address: string` (HTTP LFT base URL, e.g. `http://host:3030`)

The `Origin` header should be set to the web UI host (`http://host:8080`) for some deployments.

## Status Codes (from bundle, observed)

Common `status` values seen in API/WebSocket responses:

OK, DONE, IDLE, DENIED, LATEST,
INVALID_COMMAND, INVALID_URI, UNAUTHENTICATED, CONTENT_LENGTH_MISMATCH,
ALREADY_EXISTS, NOT_IMPLEMENTED, RESOURCE_BUSY, NOT_ASSET, INTERNAL_ERROR,
INVALID_VERSION, INVALID_ETAG, INVALID_TRANSACTION_ID, ACCESS_LOST, CONNECTION_LOST,
UNKNOWN_STATUS, TIMEOUT, OPERATION_FAILED, BUFFER_TOO_SMALL, CONTENT_BUFFER_OVERFLOW,
INVALID_PARAMETERS, NOT_INITIALIZED, ALREADY_AUTHENTICATED, INVALID_CONTENT_ID,
USER_NOT_FOUND, GROUP_NOT_FOUND, GROUP_ALREADY_EXISTS, USER_NOT_IN_GROUP, USER_ALREADY_IN_GROUP,
MOUNT_EXISTS_UNDER_PATH, TOKEN_EXPIRED, NOT_EXIST, FOLDER_NOT_EMPTY, NOT_OBJECT, PARTIALLY_COMPLETED,
QUOTA_REACHED, ALREADY_EXISTS_OTHER_TYPE, ALREADY_EXISTS_DELETED_OTHER_TYPE, PATH_HAS_CHECKPOINTS,
INVALID_CHANGE_ID

Treat `OK`, `DONE`, and sometimes `LATEST` as successful terminations. Streaming APIs may deliver multiple partials before a final status.

## Discovery (port 3333)

- Method: `DiscoverySearch.find`
- Payload (JSON inside SOWS):
  - `query.service_interface`: `{ origin: "Discovery.idl.ts", name: string, capabilities: object }`
  - `query.supported_transport`: e.g. `[{ name: "sows", meta: { marshaller: "bs", serializer: "json", ssl: "false" } }]`
  - `query.meta.deployment`: `"external"`
  - `version: 2`
- Response: includes `found` boolean and service info when present.

## Search (port 3400)

- Method: `Search.find2`
- Payload (JSON inside SOWS):
  - `version: 3`
  - `query`: `{ name: string, parent: string }`
  - `token: string` (access token)
- Response: contains `paths` on success.

Related: `Search.get_prefixes` (payload `{ version: 0 }`).

## Tagging (port 3020)

- Method: `TaggingService.get_tags`
- Payload (JSON inside SOWS):
  - `version: 3`
  - `auth_token: string`
  - `paths: string[]` (e.g., `["/"]`)
  - `show_deleted: boolean`
- Response: `status: "OK"` with tags data.

## Core Filesystem API (port 3009)

WebSocket JSON text frames. General pattern:

```json
// Request
{
  "id": 1,
  "command": "list2",
  "path": "/Users/omniverse/",
  "show_hidden": true
}

// Response (may be streaming)
{ "entries": [ ... ] }
{ "status": "DONE", "id": 1 }
```

### Commands validated

- `authorize_token`
  - See Authentication above.

- `list2`
  - Request: `{ id, command: "list2", path: string, show_hidden?: boolean }`
  - Response: streaming `entries` arrays; final `status` is typically `DONE`/`LATEST`/`OK`.

- `stat2`
  - Request: `{ id, command: "stat2", path: { path: string } }`
  - Response: metadata for the entry; we commonly read `size` (if present) and other attributes like `created_by`.

- `create_directory`
  - Request: `{ id, command: "create_directory", path: { path: string } }`
  - Response: final `status` indicates success. Some servers respond with `DONE`.

- `rename2`
  - Request:
    ```json
    {
      "id": 10,
      "command": "rename2",
      "paths_to_rename": [
        {
          "src": { "path": "/A/old" },
          "dst": { "path": "/A/new" },
          "message": "reason"
        }
      ]
    }
    ```

- `delete2`
  - Request: `{ id, command: "delete2", path: string }`

- `read` (for download redirect)
  - Request: `{ id, command: "read", uri: "/path/to/file" }`
  - Response: an intermediate message often includes `uri_redirection` (HTTP URL). Use it for HTTP GET to download content.

- `get_transaction_id`
  - Request: `{ id, command: "get_transaction_id" }`
  - Response: `{ status: "OK", transaction_id: number }`
  - Intended for large/atomic multi‑part operations; see notes in LFT section.

Other capabilities visible in the bundle but not validated here include: `create`, `update`, `create_asset[_with_hash]`, `update_asset[_with_hash]`, `create_object`, `update_object`, `deep_copy_object_struct`, `subscribe_*`, `lock/unlock`, `copy/copy2`, versioning commands, ACL commands, and mount operations.

## HTTP Large File Transfer (LFT, port 3030)

The `authorize_token` response returns an `lft_address` (e.g. `http://host:3030`). The server exposes at least one upload endpoint and provides redirect URLs for downloads.

### Upload – single‑shot (validated)

- URL: `POST http://host:3030/path/bulk/?path=<base64(pathDir)>(&message=...)(&token=<access_token>)`
- Form fields (`multipart/form-data`):
  - `size`: file size in bytes (string)
  - `path`: filename (string)
  - `data`: file content (octet‑stream)
- Behavior:
  - Returns HTTP `200 OK` with `Content-Type: application/octet-stream`, often empty body. Do not assume JSON.
  - The token is accepted as a query param; CORS headers are permissive.
  - After success, the file appears under `pathDir/filename` in listings.

Notes:
- `path` query param is the base64 of the destination directory path (trailing `/`), not the full file path.
- Server returns 405 for `GET /path/bulk/` (method is POST‑only).

### Upload – multi‑part (experimental; not working on this server)

We attempted chunked uploads by sending sequential `POST` requests with:

- Header: `Content-Range: bytes start-end/total`
- Form fields: `size: total`, `offset: start` (as hint), `path: filename`, `data: chunk`
- Query: include `transaction_id=<id>` obtained from `get_transaction_id`

Observed behavior on this server:
- Each chunk returned `200 OK` but only the first chunk persisted (final file size locked to the chunk size, e.g., 8 MB).
- This indicates the server does not assemble/append chunks for `/path/bulk/` in its current configuration.

Recommendation:
- Prefer single‑shot upload for large files on this server.
- If you must attempt multipart, increase chunk size (e.g., 128 MB) to reduce the number of parts and expect fallback to single‑shot.

### Download

Use the core API `read` command to obtain a temporary `uri_redirection` and then `GET` that URL. A 200 response returns the file bytes; MIME type may be `application/octet-stream`.

## Practical Examples

### Discovery

Method: `DiscoverySearch.find` (SOWS)

Payload:
```json
{
  "query": {
    "service_interface": {
      "origin": "Discovery.idl.ts",
      "name": "DiscoverySearch",
      "capabilities": {"find": 2}
    },
    "supported_transport": [
      {"name": "sows", "meta": {"marshaller": "bs", "serializer": "json", "ssl": "false"}}
    ],
    "meta": {"deployment": "external"}
  },
  "version": 2
}
```

### Authenticate and authorize API

1) `Credentials.auth` (SOWS): `{ version: 1, username, password } -> { access_token }`

2) `authorize_token` (JSON):
```json
{
  "token": "<access_token>",
  "version": "1.19",
  "client_capabilities": { ... },
  "id": 1,
  "command": "authorize_token"
}
```

### List directory (streaming)

Request (JSON): `{ id, command: "list2", path: "/Users/omniverse/", show_hidden: true }`

Responses: zero or more `{ entries: [...] }` followed by `{ status: "DONE" | "LATEST" | "OK" }`.

### Create directory

Request: `{ id, command: "create_directory", path: { path: "/Users/omniverse/python_test_folder/" } }`

### Stat

Request: `{ id, command: "stat2", path: { path: "/Users/omniverse/python_test_folder/" } }`

### Rename/move

Request:
```json
{
  "id": 12,
  "command": "rename2",
  "paths_to_rename": [
    {
      "src": {"path": "/Users/omniverse/old"},
      "dst": {"path": "/Users/omniverse/new"},
      "message": "Moved via Python client"
    }
  ]
}
```

### Delete

Request: `{ id, command: "delete2", path: "/Users/omniverse/python_test_folder/old" }`

### Search

Method: `Search.find2` (SOWS)

Payload: `{ version: 3, query: { name: "test", parent: "/" }, token: "<access_token>" }`

### Tagging

Method: `TaggingService.get_tags` (SOWS)

Payload: `{ version: 3, auth_token: "<access_token>", paths: ["/"], show_deleted: true }`

### Single‑shot upload (recommended for this server)

`POST http://host:3030/path/bulk/?path=<base64("/Users/omniverse/python_test_folder/")>&token=<access_token>&message=Uploaded+from+Python`

Form fields: `size`, `path` (filename), `data` (binary)

### Multipart upload (not supported here)

If the server supported append/commit semantics, a typical design would be:

1. Obtain transaction id.
2. POST chunks with `Content-Range` and the same `transaction_id`.
3. Finalize/commit transaction.

On this deployment, steps 2–3 do not result in concatenation; only the first chunk persists. Our client now detects this by verifying final size and falls back to single‑shot automatically.

## Headers & Tips

- WebSocket `Origin`: set to `http://<host>:8080` to mimic the UI.
- `User-Agent`: use a browser UA to match the UI’s environment.
- Timeouts: streaming operations like `list2` can take multiple frames; hold the socket open and aggregate entries until final status.
- Parsing: non‑API services use the binary SOWS envelope; core API is JSON text.
- HTTP uploads often return empty or octet‑stream bodies; don’t strictly require JSON responses.

## Verified Behavior vs. Hypotheses

- Verified:
  - Credentials.auth flow and token reuse across services.
  - API authorization with `authorize_token` and capability advertisement.
  - `list2`, `stat2`, `create_directory`, `rename2`, `delete2`, `read` redirection.
  - Search and Tagging methods with token.
  - Single‑shot HTTP upload via `/path/bulk/`.

- Observed but not fully working here:
  - Multipart upload with `Content-Range` and `transaction_id` (server replaced rather than appended).

- Present in bundle (not exhaustively validated):
  - Extensive capability set including versioning (`checkpoint_version`, `replace_version`, `get_checkpoints`, `get_branches`), ACLs, mounts, object/asset operations, subscriptions.

## Security Considerations

- Access tokens are sent in WebSocket payloads and as HTTP query params for LFT; protect logs and avoid leaking tokens.
- Ensure TLS/SSL in production deployments (these endpoints ran over plain HTTP/WS in this test environment).

## References

- Practical implementation: see the Python client in this repo for working payload shapes and flows.

