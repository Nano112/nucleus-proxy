import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'

const projectRoot = path.resolve(process.cwd())

function loadScript(relativePath, context) {
  const source = fs.readFileSync(path.join(projectRoot, relativePath), 'utf8')
  vm.runInNewContext(source, context, { filename: relativePath })
}

function createElement() {
  const element = {
    children: [],
    classList: {
      add() {},
      remove() {},
      toggle() {},
    },
    className: '',
    dataset: {},
    disabled: false,
    innerHTML: '',
    textContent: '',
    value: '',
    appendChild(child) {
      this.children.push(child)
    },
    addEventListener() {},
  }
  return element
}

function makeTestContext() {
  const selectorMap = new Map()

  const documentStub = {
    querySelector(selector) {
      return selectorMap.get(selector) || null
    },
    querySelectorAll() {
      return []
    },
    createElement: () => createElement(),
    addEventListener() {},
  }

  const localStorage = {
    store: new Map(),
    getItem(key) {
      return this.store.get(key) || null
    },
    setItem(key, value) {
      this.store.set(key, String(value))
    },
    removeItem(key) {
      this.store.delete(key)
    },
  }

  class FakeClient {
    constructor() {
      this.baseUrl = ''
    }
    setToken() {}
    isAuthenticated() {
      return false
    }
    async listFiles() {
      return { status: 200, data: { entries: [] } }
    }
  }

  const context = {
    console,
    window: {},
    document: documentStub,
    localStorage,
    atob(str) {
      return Buffer.from(str, 'base64').toString('binary')
    },
    fetch: async () => ({ ok: true, status: 200, headers: new Map(), json: async () => ({}) }),
    FormData: class {},
    performance: { now: () => Date.now() },
    setTimeout,
    clearTimeout,
    Map,
    Set,
  }

  context.globalThis = context
  context.window = context
  context.document = documentStub
  context.localStorage = localStorage
  context.NucleusProxyClient = FakeClient

  loadScript('app/static/js/nucleus-proxy-client.js', context)
  loadScript('app/static/js/nucleus-proxy-console.js', context)

  const selectors = {
    '#fileTableBody': Object.assign(createElement(), { appendChild(node) { this.children.push(node) } }),
    '#statusBanner': createElement(),
    '#pathInput': Object.assign(createElement(), { value: '/' }),
  }

  for (const [key, element] of Object.entries(selectors)) {
    selectorMap.set(key, element)
  }

  const rootStub = {
    querySelector: (selector) => selectorMap.get(selector) || null,
    querySelectorAll: () => [],
    createElement: () => Object.assign(createElement(), { addEventListener() {} }),
  }

  const ConsoleClass = context.NucleusProxyConsole
  const instance = new ConsoleClass({ client: new FakeClient(), root: rootStub })

  return { instance, context, selectors }
}

test('console module exports class', () => {
  const { context } = makeTestContext()
  assert.equal(typeof context.NucleusProxyConsole, 'function')
})

test('normalizePath strips duplicates and trailing slashes', () => {
  const { instance } = makeTestContext()
  assert.equal(instance._normalizePath('project///files/'), '/project/files')
  assert.equal(instance._normalizePath('///'), '/')
})

test('mergeEntriesWithPending includes virtual uploads', () => {
  const { instance } = makeTestContext()
  instance.currentPath = '/data'
  const pendingEntry = {
    path: '/data/upload.txt',
    name: 'upload.txt',
    virtual: true,
    sync_status: 'uploading',
    type: 'file',
  }
  instance.pendingUploads.set('/data/upload.txt', pendingEntry)

  const merged = instance._mergeEntriesWithPending([
    { path: '/data/report.txt', name: 'report.txt', type: 'file' },
  ])

  assert.equal(merged.length, 2)
  const names = merged.map((entry) => entry.name).sort()
  assert.deepEqual(names, ['report.txt', 'upload.txt'])
})

test('sync badge reflects status', () => {
  const { instance } = makeTestContext()

  const syncing = instance._getSyncDisplay({
    virtual: true,
    sync_status: 'Syncing to Nucleus...',
    sync_progress: 55,
  })
  assert.ok(syncing)
  assert.match(syncing.text, /Syncing/i)
  assert.match(syncing.variant, /amber/i)

  const failed = instance._getSyncDisplay({
    virtual: true,
    sync_status: 'Sync failed',
    sync_progress: 0,
  })
  assert.ok(failed)
  assert.match(failed.variant, /rose|danger/i)
})

test('renderFileRows populates table body', () => {
  const { instance, selectors } = makeTestContext()
  instance.currentPath = '/vault'

  instance.pendingUploads.set('/vault/video.mp4', {
    path: '/vault/video.mp4',
    name: 'video.mp4',
    virtual: true,
    sync_status: 'Uploading...'
  })

  instance._renderFileRows([
    { path: '/vault/photo.png', name: 'photo.png', type: 'file', modified_at: null },
  ])

  assert.equal(selectors['#fileTableBody'].children.length, 2)
  const [first] = selectors['#fileTableBody'].children
  assert.match(first.innerHTML || '', /photo\.png/)
})
