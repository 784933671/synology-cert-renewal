import type { Settings } from '../src/types'
export function settings(): Settings {
  return {
    revision: 'revision-one',
    certificate_id: 'a',
    description: 'NAS',
    domains: ['nas.example.com'],
    certificates: [
      {
        id: 'a',
        description: 'NAS',
        domains: ['nas.example.com', '*.example.com'],
      },
      { id: 'b', description: 'Second', domains: ['second.test'] },
    ],
    email: 'admin@example.com',
    renew_before_days: 2,
    secret_id_configured: true,
    secret_key_configured: true,
    probes: [{ host: '127.0.0.1', port: 5001, server_name: 'nas.example.com' }],
    schedule: {
      enabled: true,
      mode: 'hourly',
      interval_hours: 1,
      hour: 0,
      minute: 17,
    },
    notifications: {
      success_enabled: true,
      success_email: 'ok@example.com',
      failure_enabled: true,
      failure_email: 'error@example.com',
    },
    deployment_method: 'local_api',
    timezone: 'Asia/Shanghai',
  }
}
