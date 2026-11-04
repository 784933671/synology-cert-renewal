// @vitest-environment node
import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

const require = createRequire(import.meta.url)
const testUtilsRequire = createRequire(require.resolve('@vue/test-utils'))
const beautifyRequire = createRequire(testUtilsRequire.resolve('js-beautify'))
const globEntry = beautifyRequire.resolve('glob')
const globRequire = createRequire(globEntry)
const editorconfigRequire = createRequire(beautifyRequire.resolve('editorconfig'))
const probe = fileURLToPath(new URL('./fixtures/dependencies/security-probe.ts', import.meta.url))
const execute = promisify(execFile)

async function runProbe(mode: string, entry: string) {
  try {
    const { stdout } = await execute(process.execPath, ['--max-old-space-size=64', probe, mode, entry], {
      timeout: 4000,
      killSignal: 'SIGKILL',
      maxBuffer: 16 * 1024,
    })
    return JSON.parse(stdout)
  } catch (error) {
    throw new Error(`依赖安全回归失败：${mode}`, { cause: error })
  }
}

describe('开发依赖安全回归（真实消费者解析路径）', () => {
  it.each(['glob-async', 'glob-sync-stream'])('js-beautify 的 %s 取消后停止遍历', async mode => {
    expect(await runProbe(mode, globEntry)).toEqual({ reads: 1 })
  })

  it.each([
    ['glob', globRequire.resolve('minimatch')],
    ['editorconfig', editorconfigRequire.resolve('minimatch')],
  ])('%s 的 minimatch 限制预处理放大且保留正常匹配', async (_, entry) => {
    expect(await runProbe('minimatch', entry)).toEqual({ parts: 64 })
  })
})
