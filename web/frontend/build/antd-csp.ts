import type { Plugin } from 'vite'

const targets = [
  '/ant-design-vue/es/vc-util/Dom/dynamicCSS.js',
  '/@ant-design/icons-vue/es/dynamicCSS.js',
]
const anchor = "styleNode = document.createElement('style');"

export function nonceStyles(source: string): string {
  if (source.split(anchor).length !== 2) {
    throw new Error('Ant Design 样式接口已变化，请重新验证 CSP 兼容处理')
  }
  // Ant 4.2.6 的部分主题/动画样式没有传递 ConfigProvider.csp。
  return source.replace(anchor, `${anchor}
  styleNode.nonce = document.querySelector('meta[name="csp-nonce"]')?.content || '';
  `)
}

export function antdCsp(): Plugin {
  const seen = new Set<string>()
  return {
    name: 'certweb-antd-csp',
    enforce: 'pre',
    apply: 'build',
    transform(source, id) {
      const target = targets.find((path) => id.replaceAll('\\', '/').endsWith(path))
      if (!target) return
      seen.add(target)
      return { code: nonceStyles(source), map: null }
    },
    generateBundle() {
      if (seen.size !== targets.length) {
        throw new Error('未验证全部 Ant Design 样式入口，已停止构建')
      }
    },
  }
}
