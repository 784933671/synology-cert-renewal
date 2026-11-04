import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const require = createRequire(import.meta.url)
const [mode, entry] = process.argv.slice(2)

async function checkGlob() {
  const { Glob, globStreamSync } = require(entry)
  const directory = await mkdtemp(join(tmpdir(), 'certweb-glob-'))
  try {
    await Promise.all(['a/aa', 'a/ab', 'b/ba', 'b/bb'].map(async name => {
      await mkdir(join(directory, name), { recursive: true })
      await writeFile(join(directory, name, 'file.js'), 'test')
    }))
    const controller = new AbortController()
    const reason = new Error('dependency regression cancellation')
    let reads = 0
    const callbacks = []
    const read = (path, options) => {
      if (++reads === 1) controller.abort(reason)
      return readdirSync(path, options)
    }
    const fs = {
      readdir(path, options, callback) {
        const entries = read(path, options)
        callbacks.push(() => callback(null, entries))
      },
      readdirSync: read,
    }
    if (mode === 'glob-async') {
      const walker = new Glob('**', { cwd: directory, fs, signal: controller.signal })
      walker.scurry.cwd.lstatSync()
      const result = walker.walk().then(() => undefined, error => error)
      // 手动释放有限目录的读取回调，避免仅观察 Promise 已拒绝而漏掉后台遍历。
      while (callbacks.length) {
        callbacks.shift()()
        await Promise.resolve()
      }
      assert.equal(await result, reason)
    } else {
      const stream = globStreamSync('**', { cwd: directory, fs, signal: controller.signal })
      const failure = new Promise(resolve => stream.once('error', resolve))
      stream.resume()
      assert.equal(await failure, reason)
    }
    process.stdout.write(JSON.stringify({ reads }) + '\n')
    assert.equal(reads, 1, '取消后仍继续读取子目录')
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function checkMinimatch() {
  const { Minimatch } = require(entry)
  // 仅 8 段输入：旧版生成 256 项，新版必须遵守 64 项上限。
  const matcher = new Minimatch(Array(8).fill('**/../a/b').join('/'), {
    optimizationLevel: 2,
    braceExpandMax: 64,
  })
  process.stdout.write(JSON.stringify({ parts: matcher.set.length }) + '\n')
  assert.ok(matcher.set.length <= 64, '模式预处理超过配置的展开上限')
  const ordinary = new Minimatch('**/../a/b/**/../c/d', { optimizationLevel: 2 })
  assert.equal(ordinary.match('../a/b/../c/d'), true)
  assert.equal(ordinary.match('x/a/b/y/c/d'), true)
  assert.equal(ordinary.match('x/a/b/y/c/e'), false)
}

try {
  if (mode === 'minimatch') checkMinimatch()
  else if (mode === 'glob-async' || mode === 'glob-sync-stream') await checkGlob()
  else throw new Error('未知依赖回归测试模式')
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 1
}
