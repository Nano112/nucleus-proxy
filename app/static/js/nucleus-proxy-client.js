class NucleusProxyClient {
  constructor({ baseUrl = '' } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.token = null;
  }

  setToken(token) {
    this.token = token || null;
  }

  isAuthenticated() {
    return Boolean(this.token);
  }

  _authHeaders(extra = {}) {
    const headers = { ...extra };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  async _request(path, { method = 'GET', headers = {}, body, json: jsonBody } = {}) {
    const url = `${this.baseUrl}${path}`;
    const requestInit = { method, headers: this._authHeaders(headers) };
    if (jsonBody !== undefined) {
      requestInit.headers = {
        'Content-Type': 'application/json',
        ...requestInit.headers,
      };
      requestInit.body = JSON.stringify(jsonBody);
    } else if (body !== undefined) {
      requestInit.body = body;
    }
    const response = await fetch(url, requestInit);
    const contentType = response.headers.get('content-type') || '';
    let data = null;
    if (contentType.includes('application/json')) {
      data = await response.json().catch(() => null);
    } else {
      data = await response.text().catch(() => null);
    }
    if (!response.ok) {
      return { error: data || { message: response.statusText }, status: response.status };
    }
    return { data, status: response.status };
  }

  async login({ username, password }) {
    const result = await this._request('/v1/auth/login', {
      method: 'POST',
      json: { username, password },
    });
    if (!result.error && result.data?.access_token) {
      this.setToken(result.data.access_token);
    }
    return result;
  }

  async logout() {
    if (!this.token) {
      return { data: { message: 'not authenticated' }, status: 200 };
    }
    const result = await this._request('/v1/auth/logout', { method: 'POST' });
    this.setToken(null);
    return result;
  }

  async listFiles({ path = '/' } = {}) {
    const query = new URLSearchParams({ path }).toString();
    return this._request(`/v1/files/list?${query}`);
  }

  async createDirectory({ path }) {
    return this._request('/v1/files/mkdir', {
      method: 'POST',
      json: { path },
    });
  }

  async generateSignedUpload(payload) {
    return this._request('/ui/api/signed-upload', {
      method: 'POST',
      json: payload,
    });
  }

  async generateSignedDownload(payload) {
    return this._request('/ui/api/signed-download', {
      method: 'POST',
      json: payload,
    });
  }

  async uploadFile({ file, path = '/', onProgress }) {
    if (!file) {
      throw new Error('file is required');
    }
    if (file.size === 0) {
      throw new Error('File is empty');
    }

    const totalBytes = file.size;
    const errorMessageFrom = (payload, fallback) => {
      if (!payload) {
        return fallback;
      }
      if (typeof payload === 'string') {
        return payload;
      }
      if (payload.error) {
        return payload.error;
      }
      if (payload.message) {
        return payload.message;
      }
      return fallback;
    };

    const initResult = await this._request('/v1/uploads/initiate', {
      method: 'POST',
      json: {
        filename: file.name,
        size: totalBytes,
        path_dir: path,
      },
    });

    if (initResult.error) {
      throw new Error(errorMessageFrom(initResult.error, 'Failed to create upload session'));
    }

    const session = initResult.data || {};
    const uploadToken = session.upload_token;
    if (!uploadToken) {
      throw new Error('Upload session did not return a token');
    }

    const partSize = session.part_size || 8 * 1024 * 1024;
    const expectedParts = session.expected_parts || Math.max(1, Math.ceil(totalBytes / partSize));

    let uploadedBytes = 0;
    let lastSyncMeta = null;
    const startTimestamp = typeof performance !== 'undefined' ? performance.now() : Date.now();

    const emitProgress = (phase, extra = {}) => {
      if (typeof onProgress !== 'function') {
        return;
      }
      const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
      const elapsedSeconds = Math.max(0, (now - startTimestamp) / 1000);
      const proxyBytes = Math.max(0, Math.min(totalBytes, uploadedBytes));
      const proxyPercent = totalBytes ? Math.min(100, Math.max(0, (proxyBytes / totalBytes) * 100)) : 0;
      const speed = elapsedSeconds > 0 ? proxyBytes / elapsedSeconds : 0;
      const remainingProxyBytes = Math.max(0, totalBytes - proxyBytes);
      const etaSeconds = proxyBytes < totalBytes && speed > 0 ? Math.max(0, remainingProxyBytes / speed) : 0;

      const syncMeta = extra.syncMeta || null;
      const syncUploadedBytes = syncMeta && Number.isFinite(syncMeta.uploaded_bytes) ? syncMeta.uploaded_bytes : 0;
      const syncTotalBytes = syncMeta && Number.isFinite(syncMeta.total_bytes) && syncMeta.total_bytes > 0
        ? syncMeta.total_bytes
        : totalBytes;
      const combinedTotal = totalBytes + syncTotalBytes;
      const combinedLoaded = Math.min(combinedTotal, proxyBytes + syncUploadedBytes);
      const combinedPercent = combinedTotal
        ? Math.min(100, Math.max(0, (combinedLoaded / combinedTotal) * 100))
        : proxyPercent;

      onProgress({
        phase,
        loadedBytes: proxyBytes,
        totalBytes,
        percent: combinedPercent,
        proxyPercent,
        etaSeconds,
        speedBytesPerSecond: speed,
        elapsedSeconds,
        expectedParts,
        syncMeta,
        ...extra,
      });
    };

    emitProgress('uploading', { partIndex: 0 });

    const endpointBase = this.baseUrl || '';
    const authHeader = this.token ? { Authorization: `Bearer ${this.token}` } : null;

    try {
      let partIndex = 0;
      for (let offset = 0; offset < totalBytes; offset += partSize, partIndex += 1) {
        const chunkEnd = Math.min(offset + partSize, totalBytes);
        const chunk = file.slice(offset, chunkEnd);
        const form = new FormData();
        form.append('upload_token', uploadToken);
        form.append('part_index', String(partIndex));
        form.append('part_data', chunk, `${file.name}.part${partIndex}`);

        const requestInit = {
          method: 'POST',
          body: form,
        };
        if (authHeader) {
          requestInit.headers = { ...authHeader };
        }

        const response = await fetch(`${endpointBase}/v1/uploads/part`, requestInit);
        const payload = await response.json().catch(() => null);

        if (!response.ok || (payload && payload.error)) {
          const message = errorMessageFrom(payload, `Failed to upload part ${partIndex}`);
          throw new Error(message);
        }

        uploadedBytes = Math.min(totalBytes, uploadedBytes + chunk.size);
        emitProgress('uploading', { partIndex: partIndex + 1 });
      }

      uploadedBytes = totalBytes;
      emitProgress('assembling');

      const commitInit = await this._request('/v1/uploads/commit', {
        method: 'POST',
        json: { upload_token: uploadToken },
      });

      if (commitInit.error) {
        emitProgress('syncing', {
          syncState: 'failed',
          syncMeta: lastSyncMeta,
          status: commitInit.error,
        });
        throw new Error(errorMessageFrom(commitInit.error, 'Failed to commit upload'));
      }

      lastSyncMeta = commitInit.data?.sync || lastSyncMeta;
      emitProgress('syncing', { syncState: 'committing', syncMeta: lastSyncMeta, status: commitInit.data || {} });

      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const maxStatusChecks = 1800; // ~22 minutes at 750ms intervals
      const pollInterval = 750;
      let finalStatus = null;

      for (let checks = 0; checks < maxStatusChecks; checks += 1) {
        if (checks === 0) {
          await sleep(300);
        } else {
          await sleep(pollInterval);
        }

        const statusResult = await this._request('/v1/uploads/status', {
          method: 'POST',
          json: { upload_token: uploadToken },
        });

        if (statusResult.error) {
          emitProgress('syncing', {
            syncState: 'committing',
            syncMeta: lastSyncMeta,
            status: { error: statusResult.error, status: statusResult.status },
          });
          if (statusResult.status === 404) {
            break;
          }
          continue;
        }

        const statusData = statusResult.data || {};
        lastSyncMeta = statusData.sync || (statusData.meta && statusData.meta.sync) || lastSyncMeta;

        emitProgress('syncing', {
          syncState: statusData.state,
          syncMeta: lastSyncMeta,
          status: statusData,
        });

        if (statusData.state === 'completed') {
          finalStatus = statusData;
          break;
        }

        if (statusData.state === 'failed') {
          finalStatus = statusData;
          emitProgress('syncing', {
            syncState: 'failed',
            syncMeta: lastSyncMeta,
            status: statusData,
          });
          throw new Error(statusData.error || 'Upload commit failed');
        }
      }

      if (!finalStatus) {
        throw new Error('Timed out waiting for upload commit to finish.');
      }

      lastSyncMeta = {
        ...lastSyncMeta,
        status: 'completed',
        uploaded_bytes: lastSyncMeta?.uploaded_bytes ?? totalBytes,
        total_bytes: lastSyncMeta?.total_bytes ?? totalBytes,
      };

      emitProgress('syncing', {
        syncState: 'completed',
        syncMeta: lastSyncMeta,
        status: finalStatus,
      });

      emitProgress('complete', { syncMeta: lastSyncMeta });

      return {
        data: { ...finalStatus, upload_token: uploadToken },
        status: 200,
      };
    } catch (err) {
      try {
        if (uploadToken) {
          await this._request('/v1/uploads/cancel', {
            method: 'DELETE',
            json: { upload_token: uploadToken },
          });
        }
      } catch (cleanupError) {
        console.warn('Failed to cancel upload session', cleanupError);
      }
      throw err;
    }
  }

  async deleteFile({ path }) {
    return this._request('/v1/files/delete', {
      method: 'POST',
      json: { path },
    });
  }

  async rename({ src, dst, message }) {
    return this._request('/v1/files/rename', {
      method: 'POST',
      json: { src, dst, message },
    });
  }

  async stat({ path }) {
    const query = new URLSearchParams({ path }).toString();
    return this._request(`/v1/files/stat?${query}`);
  }
}

window.NucleusProxyClient = NucleusProxyClient;
