(function (global) {
  const DEFAULT_SELECTORS = {
    loginWrapper: '#loginWrapper',
    loginButton: '#loginButton',
    logoutButton: '#logoutButton',
    usernameInput: '#usernameInput',
    passwordInput: '#passwordInput',
    authStatus: '#authStatus',
    statusBanner: '#statusBanner',
    pathInput: '#pathInput',
    goPathButton: '#goPathButton',
    upPathButton: '#upPathButton',
    refreshButton: '#refreshButton',
    renameButton: '#renameButton',
    copyButton: '#copyButton',
    deleteButton: '#deleteButton',
    folderNameInput: '#folderNameInput',
    createFolderButton: '#createFolderButton',
    generateUploadUrlButton: '#generateUploadUrlButton',
    generateDownloadUrlButton: '#generateDownloadUrlButton',
    signedUrlOutput: '#signedUrlOutput',
    fileTableBody: '#fileTableBody',
    dropzone: '#dropzone',
    fileInput: '#fileInput',
    progressText: '#uploadProgressText',
    progressSecondaryText: '#uploadSecondaryText',
    progressBar: '#uploadProgressBar',
    progressBarFill: '#uploadProgressFill',
  };

  const STATUS_VARIANTS = {
    info: 'bg-blue-600/20 text-blue-200 border border-blue-500/40',
    warning: 'bg-amber-500/15 text-amber-200 border border-amber-400/30',
    success: 'bg-emerald-500/15 text-emerald-200 border border-emerald-400/30',
    danger: 'bg-rose-500/15 text-rose-200 border border-rose-500/30',
    neutral: 'bg-slate-700/40 text-slate-200 border border-slate-600/50',
  };

  class NucleusProxyConsole {
    constructor(options = {}) {
      if (!global || !global.document) {
        throw new Error('NucleusProxyConsole requires a browser environment');
      }

      this.root = options.root || global.document;
      this.selectors = { ...DEFAULT_SELECTORS, ...(options.selectors || {}) };
      this.storagePrefix = options.storagePrefix || 'nucleusProxy';
      this.storageKeys = {
        token: `${this.storagePrefix}Token`,
        user: `${this.storagePrefix}User`,
      };

      const baseUrl = options.baseUrl || '';
      this.client = options.client || new global.NucleusProxyClient({ baseUrl });

      this.currentPath = '/';
      this.currentUser = null;
      this.scopes = [];
      this.selectedEntry = null;
      this.pendingUploads = new Map();
      this.bannerTimeout = null;
      this.progressResetTimeout = null;
      this.syncTrackers = new Map();

      this.elements = this._resolveElements();
      this.controls = this._collectControls();

      this.onDirectoryChange = options.onDirectoryChange || null;
    }

    init() {
      this._bindEvents();
      this._toggleControls(false);
      this._clearFileTable('Sign in to browse files.');
      this._restoreSession();
    }

    // Initialization helpers
    _resolveElements() {
      const resolved = {};
      Object.entries(this.selectors).forEach(([key, selector]) => {
        resolved[key] = selector ? this.root.querySelector(selector) : null;
      });
      return resolved;
    }

    _collectControls() {
      const {
        pathInput,
        goPathButton,
        upPathButton,
        refreshButton,
        renameButton,
        copyButton,
        deleteButton,
        folderNameInput,
        createFolderButton,
        generateUploadUrlButton,
        generateDownloadUrlButton,
      } = this.elements;

      return [
        pathInput,
        goPathButton,
        upPathButton,
        refreshButton,
        renameButton,
        copyButton,
        deleteButton,
        folderNameInput,
        createFolderButton,
        generateUploadUrlButton,
        generateDownloadUrlButton,
      ].filter(Boolean);
    }

    _bindEvents() {
      const {
        loginButton,
        logoutButton,
        usernameInput,
        passwordInput,
        goPathButton,
        upPathButton,
        refreshButton,
        renameButton,
        copyButton,
        deleteButton,
        folderNameInput,
        createFolderButton,
        pathInput,
        generateUploadUrlButton,
        generateDownloadUrlButton,
        dropzone,
        fileInput,
      } = this.elements;

      loginButton?.addEventListener('click', () => this._handleLogin());
      logoutButton?.addEventListener('click', () => this._handleLogout());

      usernameInput?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          this._handleLogin();
        }
      });
      passwordInput?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          this._handleLogin();
        }
      });

      goPathButton?.addEventListener('click', () => {
        const target = this._normalizePath(this.elements.pathInput?.value || '/');
        this._refreshDirectory(target);
      });

      upPathButton?.addEventListener('click', () => {
        const parent = this._getParentPath(this.currentPath);
        this._refreshDirectory(parent);
      });

      refreshButton?.addEventListener('click', () => this._refreshDirectory(this.currentPath));

      pathInput?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          goPathButton?.click();
        }
      });

      renameButton?.addEventListener('click', () => this._handleRename());
      copyButton?.addEventListener('click', () => this._handleCopy());
      deleteButton?.addEventListener('click', () => this._handleDelete());

      createFolderButton?.addEventListener('click', () => this._handleCreateFolder());
      folderNameInput?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          this._handleCreateFolder();
        }
      });

      generateUploadUrlButton?.addEventListener('click', () => this._handleGenerateUploadUrl());
      generateDownloadUrlButton?.addEventListener('click', () => this._handleGenerateDownloadUrl());

      dropzone?.addEventListener('click', () => {
        if (!this._ensureAuthenticated()) {
          return;
        }
        fileInput?.click();
      });

      fileInput?.addEventListener('change', (event) => {
        const files = event.target?.files;
        if (files?.length) {
          this._handleFiles(files)
            .catch((err) => console.error('Upload failed', err))
            .finally(() => {
              if (fileInput) {
                fileInput.value = '';
              }
            });
        }
      });

      if (dropzone) {
        ['dragenter', 'dragover'].forEach((eventName) => {
          dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            event.stopPropagation();
            if (!this.client.isAuthenticated()) {
              return;
            }
            dropzone.classList.add('border-indigo-500', 'bg-slate-900/70');
          });
        });

        ['dragleave', 'drop'].forEach((eventName) => {
          dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            event.stopPropagation();
            dropzone.classList.remove('border-indigo-500', 'bg-slate-900/70');
          });
        });

        dropzone.addEventListener('drop', (event) => {
          if (!this._ensureAuthenticated()) {
            return;
          }
          const files = event.dataTransfer?.files;
          if (files?.length) {
            this._handleFiles(files).catch((err) => console.error('Upload failed', err));
          }
        });
      }
    }

    // Authentication
    async _handleLogin() {
      const { loginButton, usernameInput, passwordInput } = this.elements;
      if (!loginButton || loginButton.disabled) {
        return;
      }

      const username = usernameInput?.value.trim();
      const password = passwordInput?.value.trim();
      if (!username || !password) {
        this._showBanner('Enter your username and password.', 'danger');
        return;
      }

      loginButton.disabled = true;
      loginButton.classList.add('opacity-60');

      try {
        const result = await this.client.login({ username, password });
        if (result.error) {
          throw new Error(result.error.message || 'Login failed');
        }
        const token = result.data.access_token;
        this._setAuthenticated(token, username);
        if (passwordInput) {
          passwordInput.value = '';
        }
        this._showBanner('Authentication successful.', 'success');
        await this._refreshDirectory(this._getHomePath());
      } catch (err) {
        this._handleAuthFailure(err.message);
      } finally {
        loginButton.disabled = false;
        loginButton.classList.remove('opacity-60');
      }
    }

    async _handleLogout() {
      if (!this.client.isAuthenticated()) {
        this._handleAuthFailure();
        return;
      }
      try {
        await this.client.logout();
      } catch (err) {
        console.warn('Logout request failed', err);
      } finally {
        this._setAuthenticated(null);
        this._showBanner('Signed out.', 'info');
      }
    }

    _setAuthenticated(token, username = null, { persist = true } = {}) {
      const { loginWrapper, logoutButton, authStatus, usernameInput, passwordInput, pathInput } = this.elements;

      if (persist) {
        if (token) {
          global.localStorage.setItem(this.storageKeys.token, token);
        } else {
          global.localStorage.removeItem(this.storageKeys.token);
        }
        if (username) {
          global.localStorage.setItem(this.storageKeys.user, username);
        } else {
          global.localStorage.removeItem(this.storageKeys.user);
        }
      }

      this.client.setToken(token);
      this.currentUser = username;
      this.scopes = token ? this.client.getTokenScopes(token) : [];
      const homePath = this._getHomePath();

      if (loginWrapper) {
        loginWrapper.classList.toggle('hidden', Boolean(token));
      }
      if (logoutButton) {
        logoutButton.classList.toggle('hidden', !token);
      }
      if (authStatus) {
        authStatus.textContent = token ? `Signed in${username ? ` as ${username}` : ''}` : 'Not signed in';
      }
      if (usernameInput && !token) {
        usernameInput.value = '';
      }
      if (passwordInput) {
        passwordInput.value = '';
      }

      if (token) {
        this._toggleControls(true);
        this.selectedEntry = null;
        this._updateSelectionControls();
        this.currentPath = homePath;
        if (pathInput) {
          pathInput.value = homePath;
        }
      } else {
        this._toggleControls(false);
        this.selectedEntry = null;
        this.pendingUploads.clear();
        this.currentPath = '/';
        if (pathInput) {
          pathInput.value = '/';
        }
        this._clearFileTable('Sign in to browse files.');
      }
    }

    _handleAuthFailure(message) {
      this._setAuthenticated(null);
      if (message) {
        this._showBanner(message || 'Please sign in to continue.', 'danger');
      } else {
        this._showBanner('Please sign in to continue.', 'danger');
      }
    }

    _ensureAuthenticated() {
      if (!this.client.isAuthenticated()) {
        this._handleAuthFailure();
        return false;
      }
      return true;
    }

    _restoreSession() {
      try {
        const savedToken = global.localStorage.getItem(this.storageKeys.token);
        const savedUser = global.localStorage.getItem(this.storageKeys.user);
        if (savedToken) {
          this._setAuthenticated(savedToken, savedUser || null, { persist: false });
          this._refreshDirectory(this._getHomePath());
        }
      } catch (err) {
        console.warn('Failed to restore session', err);
        this._setAuthenticated(null, null, { persist: false });
      }
    }

    _getHomePath() {
      if (this.scopes && this.scopes.length) {
        return this._normalizePath(this.scopes[0].path);
      }
      return '/';
    }

    // UI helpers
    _toggleControls(enabled) {
      this.controls.forEach((element) => {
        if (!element) {
          return;
        }
        element.disabled = !enabled;
        element.classList.toggle('opacity-60', !enabled);
        if (element.tagName === 'BUTTON') {
          element.classList.toggle('cursor-not-allowed', !enabled);
        }
      });
      const { fileInput, dropzone } = this.elements;
      if (fileInput) {
        fileInput.disabled = !enabled;
      }
      if (dropzone) {
        dropzone.classList.toggle('pointer-events-none', !enabled);
        dropzone.classList.toggle('opacity-60', !enabled);
      }
      if (!enabled) {
        this._updateSelectionControls();
      }
    }

    _updateSelectionControls() {
      const hasSelection = Boolean(this.selectedEntry);
      const { deleteButton, renameButton, copyButton } = this.elements;
      if (deleteButton) {
        deleteButton.disabled = !hasSelection;
      }
      if (renameButton) {
        renameButton.disabled = !hasSelection;
      }
      if (copyButton) {
        copyButton.disabled = !hasSelection;
      }
    }

    _showBanner(message, variant = 'info') {
      const banner = this.elements.statusBanner;
      if (!banner) {
        return;
      }

      if (this.bannerTimeout) {
        global.clearTimeout(this.bannerTimeout);
      }

      const variants = {
        success: 'border-emerald-500/40 bg-emerald-900/40 text-emerald-100',
        danger: 'border-rose-500/40 bg-rose-900/40 text-rose-100',
        info: 'border-slate-800 bg-slate-900 text-slate-200',
        warning: 'border-amber-500/40 bg-amber-900/40 text-amber-100',
      };

      banner.textContent = message;
      banner.className = `rounded-lg border px-4 py-3 text-sm ${variants[variant] || variants.info}`;
      banner.classList.remove('hidden');

      this.bannerTimeout = global.setTimeout(() => {
        banner.classList.add('hidden');
      }, 5000);
    }

    _clearFileTable(message) {
      const body = this.elements.fileTableBody;
      if (!body) {
        return;
      }
      this.selectedEntry = null;
      this._updateSelectionControls();
      body.innerHTML = `
        <tr>
          <td colspan="5" class="px-6 py-6 text-center text-sm text-slate-400">${message}</td>
        </tr>
      `;
    }

    // Directory operations
    async _refreshDirectory(targetPath) {
      if (!this._ensureAuthenticated()) {
        return;
      }

      const path = this._normalizePath(targetPath || '/');

      try {
        const result = await this.client.listFiles({ path });
        if (result.error) {
          if (result.status === 401) {
            this._handleAuthFailure('Session expired. Please sign in again.');
            return;
          }
          if (result.status === 403 && result.error?.allowed_scopes?.length) {
            const fallbackScope = result.error.allowed_scopes[0];
            if (fallbackScope?.path) {
              this._showBanner('Access denied for current path. Redirecting to allowed scope.', 'warning');
              await this._refreshDirectory(fallbackScope.path);
              return;
            }
          }
          throw new Error(result.error.message || 'Failed to list files');
        }

        const entries = Array.isArray(result.data.entries) ? result.data.entries : [];
        this.currentPath = path;
        if (this.elements.pathInput) {
          this.elements.pathInput.value = path;
        }
        this._renderFileRows(entries);
        if (typeof this.onDirectoryChange === 'function') {
          this.onDirectoryChange({ path, entries });
        }
      } catch (err) {
        this._showBanner(err.message || 'Failed to list files.', 'danger');
      }
    }

    _mergeEntriesWithPending(entries) {
      const entryMap = new Map();
      entries.forEach((entry) => {
        const normalizedPath = this._normalizePath(entry.path || `${this.currentPath.replace(/\/$/, '')}/${entry.name}`);
        const normalized = {
          ...entry,
          path: normalizedPath,
          name: entry.name || (normalizedPath === '/' ? '(root)' : normalizedPath.split('/').pop()),
        };
        entryMap.set(normalized.path, normalized);
      });

      this.pendingUploads.forEach((pendingEntry, key) => {
        if (!entryMap.has(key)) {
          entryMap.set(key, pendingEntry);
        }
      });

      return Array.from(entryMap.values());
    }

    _renderFileRows(entries) {
      const body = this.elements.fileTableBody;
      if (!body) {
        return;
      }

      const mergedEntries = this._mergeEntriesWithPending(entries);

      if (!mergedEntries.length) {
        this._clearFileTable('Folder is empty.');
        return;
      }

      body.innerHTML = '';
      this.selectedEntry = null;
      this._updateSelectionControls();

      const sorted = [...mergedEntries].sort((a, b) => {
        const aDir = this._isDirectoryEntry(a);
        const bDir = this._isDirectoryEntry(b);
        if (aDir === bDir) {
          return (a.name || '').localeCompare(b.name || '');
        }
        return aDir ? -1 : 1;
      });

      sorted.forEach((entry) => {
        const row = this.root.createElement('tr');
        row.className = 'group cursor-pointer hover:bg-slate-800/40 transition-colors';

        const entryPath = this._normalizePath(entry.path || `${this.currentPath.replace(/\/$/, '')}/${entry.name}`);
        const isDir = this._isDirectoryEntry(entry);
        const displayName = entry.name || (entryPath === '/' ? '(root)' : entryPath);
        const sizeText = entry.size ? this._formatBytes(entry.size) : '';
        const modifiedText = entry.modified_at ? new Date(entry.modified_at).toLocaleString() : '';

        const syncInfo = this._getSyncDisplay(entry);
        const badgeHtml = syncInfo ? `<span class="ml-2 inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${syncInfo.variant}">${syncInfo.text}</span>` : '';

        row.innerHTML = `
          <td class="px-6 py-3">
            <div class="flex items-center gap-2">
              <span class="inline-flex h-6 w-6 items-center justify-center rounded-full bg-slate-800 text-xs text-slate-300 transition-colors group-hover:bg-indigo-600 group-hover:text-indigo-50">
                ${isDir ? '📁' : '📄'}
              </span>
              <span class="${entry.virtual ? 'opacity-70' : ''}">${displayName}${isDir ? ' /' : ''}</span>
              ${badgeHtml}
            </div>
          </td>
          <td class="px-6 py-3 text-sm text-slate-400">${entry.type ?? 'file'}</td>
          <td class="px-6 py-3 text-sm text-slate-400">${sizeText}</td>
          <td class="px-6 py-3 text-sm text-slate-400">${modifiedText || (entry.virtual ? 'Uploading…' : '')}</td>
          <td class="px-6 py-3 text-sm text-slate-400">${entry.created_by ?? ''}</td>
        `;

        row.dataset.path = entryPath;

        row.addEventListener('dblclick', () => {
          if (isDir) {
            this._refreshDirectory(entryPath);
          }
        });

        row.addEventListener('click', () => {
          this.root.querySelectorAll('#fileTableBody tr').forEach((otherRow) => {
            otherRow.classList.remove('bg-slate-800/60');
          });
          row.classList.add('bg-slate-800/60');
          this.selectedEntry = {
            path: entryPath,
            isDirectory: isDir,
            name: displayName,
            raw: entry,
          };
          this._updateSelectionControls();
        });

        body.appendChild(row);
      });
    }

    _getSyncDisplay(entry) {
      const status = (entry.sync_status || entry.syncStatus || '').toString();
      const uploadState = (entry.upload_state || entry.uploadState || '').toString().toLowerCase();
      const isVirtual = Boolean(entry.virtual || entry.is_virtual);
      if (!isVirtual) {
        return null;
      }

      const lowered = status.toLowerCase();
      const progress = typeof entry.sync_progress === 'number' ? Math.round(entry.sync_progress) : null;
      let variant = STATUS_VARIANTS.neutral;
      let label = status || 'Pending';

      if (lowered.includes('fail')) {
        variant = STATUS_VARIANTS.danger;
      } else if (lowered.includes('sync') && lowered.includes('complete')) {
        variant = STATUS_VARIANTS.success;
      } else if (lowered.includes('upload')) {
        variant = STATUS_VARIANTS.info;
      } else if (lowered.includes('sync')) {
        variant = STATUS_VARIANTS.warning;
      } else if (uploadState === 'pending') {
        variant = STATUS_VARIANTS.info;
        label = 'Uploading…';
      } else if (uploadState === 'committing' || uploadState === 'assembling') {
        variant = STATUS_VARIANTS.warning;
        label = 'Syncing to Nucleus…';
      }

      if (progress !== null && !Number.isNaN(progress)) {
        label = `${label} (${progress}%)`;
      }

      if (!label) {
        label = uploadState ? uploadState.charAt(0).toUpperCase() + uploadState.slice(1) : 'Pending';
      }

      return { text: label, variant };
    }

    // CRUD handlers
    async _handleRename() {
      if (!this._ensureAuthenticated()) {
        return;
      }
      if (!this.selectedEntry) {
        this._showBanner('Select a file or folder to rename.', 'danger');
        return;
      }

      const target = { ...this.selectedEntry };
      const currentName = target.name || target.path.split('/').pop() || 'item';
      const newName = global.prompt(`Rename ${target.isDirectory ? 'folder' : 'file'}:`, currentName);
      if (!newName || newName === currentName) {
        return;
      }

      const pathParts = target.path.split('/');
      pathParts[pathParts.length - 1] = newName;
      const newPath = pathParts.join('/');

      const { renameButton } = this.elements;
      if (renameButton) {
        renameButton.disabled = true;
      }

      try {
        const result = await this.client.rename({
          src: target.path,
          dst: newPath,
          message: `Renamed ${currentName} to ${newName}`,
        });
        if (result.error) {
          const payload = result.error;
          const message = (payload && (payload.message || payload.error)) || 'Failed to rename item';
          throw new Error(message);
        }
        this._showBanner(`${currentName} renamed to ${newName}.`, 'success');
        this.selectedEntry = null;
        this._updateSelectionControls();
        await this._refreshDirectory(this.currentPath);
      } catch (err) {
        this._showBanner(err.message || `Failed to rename ${currentName}`, 'danger');
        this._updateSelectionControls();
      }
    }

    async _handleCopy() {
      if (!this._ensureAuthenticated()) {
        return;
      }
      if (!this.selectedEntry) {
        this._showBanner('Select a file or folder to copy.', 'danger');
        return;
      }

      const target = { ...this.selectedEntry };
      const currentName = target.name || target.path.split('/').pop() || 'item';
      const suggestedName = currentName.includes('.')
        ? currentName.replace(/(\.[^.]+)$/, '_copy$1')
        : `${currentName}_copy`;
      const newName = global.prompt(`Copy ${target.isDirectory ? 'folder' : 'file'} as:`, suggestedName);
      if (!newName) {
        return;
      }

      const dirPath = target.path.substring(0, target.path.lastIndexOf('/')) || '/';
      const newPath = dirPath === '/' ? `/${newName}` : `${dirPath}/${newName}`;

      const { copyButton } = this.elements;
      if (copyButton) {
        copyButton.disabled = true;
      }

      try {
        const result = await this.client.copy({
          src: target.path,
          dst: newPath,
          message: `Copied ${currentName} to ${newName}`,
        });
        if (result.error) {
          const payload = result.error;
          const message = (payload && (payload.message || payload.error)) || 'Failed to copy item';
          throw new Error(message);
        }
        this._showBanner(`${currentName} copied to ${newName}.`, 'success');
        this.selectedEntry = null;
        this._updateSelectionControls();
        await this._refreshDirectory(this.currentPath);
      } catch (err) {
        this._showBanner(err.message || `Failed to copy ${currentName}`, 'danger');
        this._updateSelectionControls();
      }
    }

    async _handleDelete() {
      if (!this._ensureAuthenticated()) {
        return;
      }
      if (!this.selectedEntry) {
        this._showBanner('Select a file or folder to delete.', 'danger');
        return;
      }

      const target = { ...this.selectedEntry };
      const itemLabel = target.name || target.path || 'item';
      const confirmMessage = target.isDirectory
        ? `Delete folder ${itemLabel}?`
        : `Delete file ${itemLabel}?`;
      if (!global.confirm(confirmMessage)) {
        return;
      }

      const { deleteButton } = this.elements;
      if (deleteButton) {
        deleteButton.disabled = true;
      }

      try {
        let deletePath = target.path;
        if (target.isDirectory && !deletePath.endsWith('/')) {
          deletePath = `${deletePath}/`;
        }
        const result = await this.client.deleteFile({ path: deletePath });
        if (result.error) {
          const payload = result.error;
          const message = (payload && (payload.message || payload.error)) || 'Failed to delete item';
          throw new Error(message);
        }
        this._showBanner(`${itemLabel} deleted.`, 'success');
        this.selectedEntry = null;
        this._updateSelectionControls();
        await this._refreshDirectory(this.currentPath);
      } catch (err) {
        this._showBanner(err.message || `Failed to delete ${itemLabel}`, 'danger');
        this._updateSelectionControls();
      }
    }

    async _handleCreateFolder() {
      if (!this._ensureAuthenticated()) {
        return;
      }
      const { folderNameInput } = this.elements;
      const name = folderNameInput?.value.trim();
      if (!name) {
        this._showBanner('Folder name is required.', 'danger');
        return;
      }

      const base = this.currentPath === '/' ? '' : this.currentPath;
      const targetPath = this._normalizePath(`${base}/${name}`);

      try {
        const result = await this.client.createDirectory({ path: targetPath });
        if (result.error) {
          throw new Error(result.error.message || 'Failed to create folder');
        }
        if (folderNameInput) {
          folderNameInput.value = '';
        }
        this._showBanner('Folder created successfully.', 'success');
        await this._refreshDirectory(this.currentPath);
      } catch (err) {
        this._showBanner(err.message || 'Failed to create folder.', 'danger');
      }
    }

    async _handleGenerateUploadUrl() {
      if (!this._ensureAuthenticated()) {
        return;
      }
      try {
        const body = {
          filename: 'upload.bin',
          file_size: 1024,
          path_dir: this.currentPath,
        };
        const result = await this.client.generateSignedUpload(body);
        if (result.error) {
          if (result.status === 401) {
            this._handleAuthFailure('Session expired. Please sign in again.');
            return;
          }
          throw new Error(result.error.message || 'Failed to create upload URL');
        }
        if (this.elements.signedUrlOutput) {
          this.elements.signedUrlOutput.value = JSON.stringify(result.data, null, 2);
        }
        this._showBanner('Upload URL generated.', 'success');
      } catch (err) {
        this._showBanner(err.message || 'Failed to generate upload URL.', 'danger');
      }
    }

    async _handleGenerateDownloadUrl() {
      if (!this._ensureAuthenticated()) {
        return;
      }
      try {
        const result = await this.client.generateSignedDownload({ file_path: this.currentPath });
        if (result.error) {
          if (result.status === 401) {
            this._handleAuthFailure('Session expired. Please sign in again.');
            return;
          }
          throw new Error(result.error.message || 'Failed to create download URL');
        }
        if (this.elements.signedUrlOutput) {
          this.elements.signedUrlOutput.value = JSON.stringify(result.data, null, 2);
        }
        this._showBanner('Download URL generated.', 'success');
      } catch (err) {
        this._showBanner(err.message || 'Failed to generate download URL.', 'danger');
      }
    }

    // Upload helpers
    _addPendingUpload(path, info) {
      this.pendingUploads.set(path, {
        path,
        name: info.name,
        type: 'file',
        size: info.size,
        sync_status: info.syncStatus || 'Uploading…',
        sync_progress: info.progress || 0,
        uploadToken: info.uploadToken || null,
        startTime: Date.now(),
        virtual: true,
      });
      this._refreshDirectory(this.currentPath);
    }

    _updatePendingUpload(path, status) {
      if (!this.pendingUploads.has(path)) {
        return;
      }
      const info = this.pendingUploads.get(path);
      if (!info) {
        return;
      }
      info.sync_status = status;
      if (status === 'completed' || status === 'failed') {
        global.setTimeout(() => {
          this.pendingUploads.delete(path);
          this._refreshDirectory(this.currentPath);
        }, 2000);
      } else {
        this.pendingUploads.set(path, info);
      }
    }

    async _trackSyncStatus(uploadToken, filename, path) {
      if (!uploadToken) {
        return;
      }
      const trackerKey = `${uploadToken}:${path}`;
      if (this.syncTrackers.has(trackerKey)) {
        return;
      }
      this.syncTrackers.set(trackerKey, true);

      const maxChecks = 120;
      const checkInterval = 1000;

      for (let i = 0; i < maxChecks; i += 1) {
        await new Promise((resolve) => global.setTimeout(resolve, checkInterval));
        try {
          const statusResult = await this.client._request('/v1/uploads/status', {
            method: 'POST',
            json: { upload_token: uploadToken },
          });
          if (statusResult.error || !statusResult.data) {
            break;
          }
          const status = statusResult.data;
          if (status.sync?.uploaded_bytes && status.sync?.total_bytes) {
            const progress = Math.min(100, Math.round((status.sync.uploaded_bytes / status.sync.total_bytes) * 100));
            const pendingEntry = this.pendingUploads.get(path);
            if (pendingEntry) {
              pendingEntry.sync_progress = progress;
              pendingEntry.sync_status = progress >= 100 ? 'completed' : 'syncing';
              this.pendingUploads.set(path, pendingEntry);
              this._refreshDirectory(this.currentPath);
            }
          }

          if (status.state === 'completed' || status.sync?.status === 'completed') {
            this._showBanner(`${filename} synced successfully.`, 'success');
            break;
          }

          if (status.state === 'failed') {
            this._showBanner(`${filename} sync failed.`, 'danger');
            this._updatePendingUpload(path, 'failed');
            break;
          }
        } catch (err) {
          console.warn(`Sync status check ended for ${filename}`, err);
          break;
        }
      }

      this.syncTrackers.delete(trackerKey);
    }

    async _handleFiles(fileList) {
      if (!this._ensureAuthenticated()) {
        return;
      }

      const files = Array.from(fileList || []);
      if (!files.length) {
        return;
      }

      this._toggleControls(false);
      if (this.progressResetTimeout) {
        global.clearTimeout(this.progressResetTimeout);
        this.progressResetTimeout = null;
      }

      const { progressBar, progressBarFill, progressText, progressSecondaryText } = this.elements;

      try {
        for (const file of files) {
          progressBar?.classList.remove('hidden');
          if (progressBarFill) {
            progressBarFill.style.width = '0%';
          }
          if (progressText) {
            progressText.textContent = `Preparing ${file.name}...`;
          }
          if (progressSecondaryText) {
            progressSecondaryText.textContent = '';
          }

          let lastSyncMeta = null;
          const entryPath = this._normalizePath(`${this.currentPath.replace(/\/$/, '')}/${file.name}`);

          const updateProgress = (progress) => {
            if (!progress) {
              return;
            }
            if (progress.status && progress.status.error && progressText) {
              const errorInfo = progress.status.error;
              const errorText = typeof errorInfo === 'string' ? errorInfo : (errorInfo.message || JSON.stringify(errorInfo));
              progressText.textContent = `Sync error: ${errorText}`;
              if (progressSecondaryText) {
                progressSecondaryText.textContent = '';
              }
            }

            const phase = progress.phase || 'uploading';
            const totalBytes = Number.isFinite(progress.totalBytes) ? progress.totalBytes : file.size;
            const uploadedProxyBytes = Number.isFinite(progress.loadedBytes) ? progress.loadedBytes : 0;
            const syncMeta = progress.syncMeta || lastSyncMeta || {};

            if (progress.syncMeta) {
              lastSyncMeta = progress.syncMeta;
            }

            const syncUploadedBytes = Number.isFinite(syncMeta.uploaded_bytes) ? syncMeta.uploaded_bytes : 0;
            const syncTotalBytes = Number.isFinite(syncMeta.total_bytes) && syncMeta.total_bytes > 0
              ? syncMeta.total_bytes
              : totalBytes;

            const combinedTotal = totalBytes + syncTotalBytes;
            const combinedLoaded = Math.min(combinedTotal, uploadedProxyBytes + syncUploadedBytes);
            const overallPercent = combinedTotal
              ? Math.min(100, Math.max(0, (combinedLoaded / combinedTotal) * 100))
              : 0;

            if (progressBarFill) {
              progressBarFill.style.width = `${overallPercent}%`;
            }

            if (phase === 'uploading') {
              const proxyPercent = totalBytes
                ? Math.min(100, Math.max(0, (uploadedProxyBytes / totalBytes) * 100))
                : 0;
              const etaText = this._formatEta(progress.etaSeconds);
              const speedText = this._formatSpeed(progress.speedBytesPerSecond);
              if (progressText) {
                progressText.textContent = `Uploading ${file.name}: ${proxyPercent.toFixed(1)}%`;
              }
              if (progressSecondaryText) {
                progressSecondaryText.textContent = `ETA ${etaText}${speedText !== '--' ? ` | ${speedText}` : ''}`;
              }
              const pendingEntry = this.pendingUploads.get(entryPath);
              if (pendingEntry) {
                pendingEntry.sync_progress = Math.round(proxyPercent);
                pendingEntry.sync_status = 'uploading';
                this.pendingUploads.set(entryPath, pendingEntry);
                this._refreshDirectory(this.currentPath);
              }
            } else if (phase === 'assembling') {
              if (progressText) {
                progressText.textContent = `Preparing ${file.name} for sync...`;
              }
              if (progressSecondaryText) {
                progressSecondaryText.textContent = '';
              }
            } else if (phase === 'syncing') {
              const syncState = progress.syncState || (progress.status && progress.status.state) || 'committing';
              const syncPercent = syncTotalBytes
                ? Math.min(100, Math.max(0, (syncUploadedBytes / syncTotalBytes) * 100))
                : 0;
              let stateLabel = 'Syncing to Nucleus';
              if (syncState === 'completed') {
                stateLabel = 'Sync complete';
              } else if (syncState === 'failed') {
                stateLabel = 'Sync failed';
              } else if (syncState === 'assembling') {
                stateLabel = 'Preparing sync';
              }
              if (progressText) {
                progressText.textContent = `${stateLabel}: ${syncPercent.toFixed(1)}%`;
              }
              if (progressSecondaryText) {
                progressSecondaryText.textContent = `Proxy upload 100% | Sync progress ${syncPercent.toFixed(1)}%`;
              }
              const pendingEntry = this.pendingUploads.get(entryPath);
              if (pendingEntry) {
                pendingEntry.sync_progress = Math.round(syncPercent);
                pendingEntry.sync_status = syncState === 'failed' ? 'failed' : 'syncing';
                this.pendingUploads.set(entryPath, pendingEntry);
                this._refreshDirectory(this.currentPath);
              }
            } else if (phase === 'complete') {
              const duration = this._formatDuration(progress.elapsedSeconds);
              const sizeText = this._formatBytes(file.size);
              if (progressBarFill) {
                progressBarFill.style.width = '100%';
              }
              if (progressText) {
                progressText.textContent = `${file.name} uploaded${sizeText ? ` (${sizeText})` : ''} in ${duration}.`;
              }
              if (progressSecondaryText) {
                progressSecondaryText.textContent = 'Synced to Nucleus successfully.';
              }
              const pendingEntry = this.pendingUploads.get(entryPath);
              if (pendingEntry) {
                pendingEntry.sync_progress = 100;
                pendingEntry.sync_status = 'completed';
                this.pendingUploads.set(entryPath, pendingEntry);
                this._refreshDirectory(this.currentPath);
              }
            }
          };

          const skipSync = file.size > 10 * 1024 * 1024;
          if (skipSync) {
            this._addPendingUpload(entryPath, {
              name: file.name,
              size: file.size,
              uploadToken: null,
              syncStatus: 'uploading',
              progress: 0,
            });
          }

          try {
            const result = await this.client.uploadFile({
              file,
              path: this.currentPath,
              onProgress: (progress) => {
                updateProgress(progress);
                if (skipSync && progress.phase) {
                  if (progress.phase === 'syncing') {
                    this._updatePendingUpload(entryPath, 'syncing');
                  } else if (progress.phase === 'complete') {
                    this._updatePendingUpload(entryPath, 'completed');
                  }
                }
              },
              skipSyncWait: skipSync,
            });

            if (skipSync) {
              this._showBanner(`${file.name} uploaded. Syncing in background...`, 'success');
              this._updatePendingUpload(entryPath, 'syncing');
              if (result.data?.upload_token) {
                const pendingEntry = this.pendingUploads.get(entryPath);
                if (pendingEntry) {
                  pendingEntry.uploadToken = result.data.upload_token;
                  this.pendingUploads.set(entryPath, pendingEntry);
                  this._trackSyncStatus(result.data.upload_token, file.name, entryPath)
                    .then(() => this._updatePendingUpload(entryPath, 'completed'))
                    .catch(() => this._updatePendingUpload(entryPath, 'failed'));
                }
              }
            } else {
              this._showBanner(`${file.name} uploaded successfully.`, 'success');
              await this._refreshDirectory(this.currentPath);
            }
          } catch (err) {
            if (progressSecondaryText) {
              progressSecondaryText.textContent = '';
            }
            this._showBanner(err.message || `Failed to upload ${file.name}`, 'danger');
            break;
          } finally {
            if (this.progressResetTimeout) {
              global.clearTimeout(this.progressResetTimeout);
            }
            this.progressResetTimeout = global.setTimeout(() => {
              if (progressBarFill) {
                progressBarFill.style.width = '0%';
              }
              progressBar?.classList.add('hidden');
              if (progressText) {
                progressText.textContent = '';
              }
              if (progressSecondaryText) {
                progressSecondaryText.textContent = '';
              }
              this.progressResetTimeout = null;
            }, 1800);
          }
        }
      } finally {
        this._toggleControls(true);
      }
    }

    // Formatting helpers
    _normalizePath(path) {
      if (!path) {
        return '/';
      }
      let normalized = String(path).replace(/\\+/g, '/');
      if (!normalized.startsWith('/')) {
        normalized = `/${normalized}`;
      }
      normalized = normalized.replace(/\/+/g, '/');
      if (normalized.length > 1 && normalized.endsWith('/')) {
        normalized = normalized.replace(/\/+$/, '');
      }
      return normalized || '/';
    }

    _getParentPath(path) {
      const normalized = this._normalizePath(path);
      if (normalized === '/') {
        return '/';
      }
      const parent = normalized.substring(0, normalized.lastIndexOf('/')) || '/';
      return parent;
    }

    _isDirectoryEntry(entry) {
      const type = (entry?.type || entry?.path_type || '').toString().toLowerCase();
      return type === 'directory' || type === 'folder' || type === 'mount';
    }

    _formatBytes(bytes) {
      if (!Number.isFinite(bytes) || bytes < 0) {
        return '';
      }
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let value = bytes;
      let unitIndex = 0;
      while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
      }
      const decimals = value >= 100 || unitIndex === 0 ? 0 : value >= 10 ? 1 : 2;
      return `${value.toFixed(decimals)} ${units[unitIndex]}`;
    }

    _formatDuration(seconds) {
      if (!Number.isFinite(seconds) || seconds <= 0) {
        return '0s';
      }
      const rounded = Math.round(seconds);
      const hours = Math.floor(rounded / 3600);
      const minutes = Math.floor((rounded % 3600) / 60);
      const secs = Math.max(1, rounded % 60);
      const parts = [];
      if (hours) {
        parts.push(`${hours}h`);
      }
      if (hours || minutes) {
        parts.push(`${minutes}m`);
      }
      parts.push(`${secs}s`);
      return parts.join(' ');
    }

    _formatEta(seconds) {
      if (!Number.isFinite(seconds) || seconds <= 0) {
        return 'estimating...';
      }
      return this._formatDuration(seconds);
    }

    _formatSpeed(bytesPerSecond) {
      if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) {
        return '--';
      }
      if (bytesPerSecond >= 1024 * 1024) {
        return `${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MB/s`;
      }
      return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`;
    }
  }

  global.NucleusProxyConsole = NucleusProxyConsole;
})(typeof window !== 'undefined' ? window : globalThis);
