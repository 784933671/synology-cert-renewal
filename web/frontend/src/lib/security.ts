import type { SecurityDevice } from '../types'
export function deviceText(device: SecurityDevice) {
  return ({ desktop: '电脑', mobile: '手机', tablet: '平板', other: '其他设备', unknown: '未知设备' } as Record<string, string>)[device] || '未知设备'
}
