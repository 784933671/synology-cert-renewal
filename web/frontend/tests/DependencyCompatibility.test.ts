import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { defineComponent, shallowRef } from 'vue'
import { mount, type VueWrapper } from '@vue/test-utils'

const require = createRequire(import.meta.url)
const testUtilsRequire = createRequire(require.resolve('@vue/test-utils'))
const beautifyRequire = createRequire(testUtilsRequire.resolve('js-beautify'))
const editorconfig = beautifyRequire('editorconfig')
const beautifyCli = beautifyRequire.resolve('./bin/js-beautify.js')
const execute = promisify(execFile)
const directories: string[] = []
let wrapper: VueWrapper | undefined

async function createProject() {
  const directory = await mkdtemp(join(tmpdir(), 'certweb 中文 [兼容] '))
  directories.push(directory)
  await Promise.all(['nested/deeper', 'node_modules', '.git'].map(name => mkdir(join(directory, name), { recursive: true })))
  await Promise.all([
    writeFile(join(directory, '.editorconfig'), 'root = true\n[*]\nindent_style = space\nindent_size = 2\nend_of_line = lf\ninsert_final_newline = true\n\n[*.js]\ncharset = utf-8\n\n[nested/**/*.js]\nmax_line_length = 100\n'),
    writeFile(join(directory, 'nested', '.editorconfig'), '[*.js]\nindent_size = 4\n'),
    writeFile(join(directory, 'root.js'), 'function root(){return 1;}'),
    writeFile(join(directory, 'nested', 'deeper', 'child.js'), 'function child(){return 2;}'),
    writeFile(join(directory, 'nested', 'deeper', 'index.html'), '<section><p>证书</p></section>'),
    writeFile(join(directory, 'nested', 'deeper', 'readme.txt'), 'unchanged'),
    writeFile(join(directory, 'node_modules', 'ignored.js'), 'const ignored={untouched:true};'),
    writeFile(join(directory, '.git', 'ignored.js'), 'const ignored={untouched:true};'),
  ])
  return directory
}

afterEach(async () => {
  wrapper?.unmount()
  wrapper = undefined
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })))
})

describe('安全依赖升级的消费者兼容性', () => {
  it.each(['parseSync', 'parse'])('EditorConfig %s 保留父子级联及嵌套通配符', async method => {
    const directory = await createProject()
    const root = await editorconfig[method](join(directory, 'root.js'))
    const child = await editorconfig[method](join(directory, 'nested', 'deeper', 'child.js'))
    const text = await editorconfig[method](join(directory, 'nested', 'deeper', 'readme.txt'))
    expect(root).toMatchObject({ indent_style: 'space', indent_size: 2, charset: 'utf-8', end_of_line: 'lf' })
    expect(root.max_line_length).toBeUndefined()
    expect(child).toMatchObject({ indent_style: 'space', indent_size: 4, charset: 'utf-8', max_line_length: 100, insert_final_newline: true })
    expect(text).toMatchObject({ indent_size: 2 })
    expect(text.charset).toBeUndefined()
    expect(text.max_line_length).toBeUndefined()
  })

  it('js-beautify CLI 展开 brace glob、读取 EditorConfig 并跳过依赖和 Git 目录', async () => {
    const directory = await createProject()
    await execute(process.execPath, [beautifyCli, '--editorconfig', '--replace', '**/*.{js,html}'], {
      cwd: directory,
      timeout: 4000,
      maxBuffer: 16 * 1024,
    })
    expect(await readFile(join(directory, 'root.js'), 'utf8')).toBe('function root() {\n  return 1;\n}\n')
    expect(await readFile(join(directory, 'nested', 'deeper', 'child.js'), 'utf8')).toBe('function child() {\n    return 2;\n}\n')
    expect(await readFile(join(directory, 'nested', 'deeper', 'index.html'), 'utf8')).toBe('<section>\n  <p>证书</p>\n</section>\n')
    expect(await readFile(join(directory, 'nested', 'deeper', 'readme.txt'), 'utf8')).toBe('unchanged')
    expect(await readFile(join(directory, 'node_modules', 'ignored.js'), 'utf8')).toBe('const ignored={untouched:true};')
    expect(await readFile(join(directory, '.git', 'ignored.js'), 'utf8')).toBe('const ignored={untouched:true};')
  })

  it('Vue Test Utils 的 HTML 格式化、转义和交互输出保持兼容', async () => {
    const Component = defineComponent({
      setup() {
        const count = shallowRef(0)
        return { count, label: '<安全>' }
      },
      template: '<section><p>{{ label }}</p><button @click="count++">检查 {{ count }}</button></section>',
    })
    wrapper = mount(Component)
    expect(wrapper.html()).toBe('<section>\n  <p>&lt;安全&gt;</p><button>检查 0</button>\n</section>')
    await wrapper.get('button').trigger('click')
    expect(wrapper.html()).toBe('<section>\n  <p>&lt;安全&gt;</p><button>检查 1</button>\n</section>')
    expect(wrapper.get('p').text()).toBe('<安全>')
  })
})
