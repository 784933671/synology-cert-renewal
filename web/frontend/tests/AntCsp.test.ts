import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { nonceStyles } from '../build/antd-csp'

afterEach(() => {
  document.head.innerHTML = ''
})

describe('Ant Design CSP 样式适配', () => {
  for (const path of [
    'ant-design-vue/es/vc-util/Dom/dynamicCSS.js',
    '@ant-design/icons-vue/es/dynamicCSS.js',
  ]) {
    it(`${path} 在插入和更新样式时保留本页 nonce`, () => {
      const meta = document.createElement('meta')
      meta.name = 'csp-nonce'
      meta.content = 'per-response-test-nonce'
      document.head.appendChild(meta)
      const source = readFileSync(resolve('node_modules', path), 'utf8')
      const executable = nonceStyles(source).replace(/^import .+;$/gm, '').replace(/export /g, '')
      const { updateCSS } = new Function('document', 'window', `
        const contains = (root, node) => root.contains(node);
        ${path.startsWith('ant-design-vue') ? 'const canUseDom = () => true;' : ''}
        ${path.startsWith('ant-design-vue') ? executable : executable.replace(/function contains\([\s\S]+?(?=var APPEND_ORDER)/, '')}
        return { updateCSS };
      `)(document, window)
      const first = updateCSS('.fixture { color: red }', 'fixture')
      expect(first.nonce).toBe(meta.content)
      expect(document.head.contains(first)).toBe(true)
      const second = updateCSS('.fixture { color: blue }', 'fixture')
      expect(second).toBe(first)
      expect(second.nonce).toBe(meta.content)
      expect(second.textContent).toContain('blue')
      expect(updateCSS('@keyframes fixture { to { opacity: 1 } }', 'effect').nonce).toBe(meta.content)
    })
  }

  it('上游实现变化时停止构建', () => {
    expect(() => nonceStyles('upstream changed')).toThrow('接口已变化')
    const anchor = "styleNode = document.createElement('style');"
    expect(() => nonceStyles(anchor + anchor)).toThrow('接口已变化')
  })
})
