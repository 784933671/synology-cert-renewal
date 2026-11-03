export interface Session {
  username: string
  csrf_token: string
  must_change_password: boolean
}
export interface Probe {
  host: string
  port: number
  server_name: string
}
export interface Schedule {
  enabled: boolean
  mode: 'hourly' | 'daily' | 'unsupported'
  interval_hours: number
  hour: number
  minute: number
  editable?: boolean
  message?: string
}
export interface Notifications {
  success_enabled: boolean
  success_email: string
  failure_enabled: boolean
  failure_email: string
}
export interface CertificateChoice {
  id: string
  description: string
  domains: string[]
  available?: boolean
  selectable?: boolean
  reason?: string
}
export interface Settings {
  revision: string
  certificate_id: string
  description: string
  domains: string[]
  certificates: CertificateChoice[]
  email: string
  renew_before_days: number
  secret_id_configured: boolean
  secret_key_configured: boolean
  probes: Probe[]
  schedule: Schedule
  notifications: Notifications
  deployment_method: string
  timezone: string
}
export interface Draft {
  certificate_id: string
  email: string
  renew_before_days: number
  secret_id: string
  secret_key: string
  probes: Probe[]
  schedule: Schedule
  notifications: Notifications
}
export interface FailureReport {
  at?: string
  stage?: string
  stage_label?: string
  summary?: string
  code?: string
  message?: string
  hint?: string
  archive_path?: string
  archive_error?: string
}
export interface RunResult {
  at?: string
  success?: boolean
  message?: string
  failure?: FailureReport
}
export interface Status {
  certificate: {
    id: string
    description: string
    domains: string[]
    not_after: string
    fingerprint: string
    remaining_seconds: number
    renew_at: string
  }
  renew_before_days: number
  task: {
    enabled: boolean
    running: boolean
    schedule_text: string
    last_run:
      | string
      | {
          start_time?: string
          stop_time?: string
          exit_code?: number
          exit_type?: string
        }
      | null
  }
  last_result: RunResult | null
  pending: {
    deployment: boolean
    dns_cleanup: boolean | number
    notification: boolean
    interrupted: boolean
  }
  check: { running: boolean; last_result: RunResult | null }
  server_time: string
  timezone: string
}
export interface FailureItem {
  id: string
  at: string
  stage_label: string
  summary: string
  code: string
}
export interface FailureDetail {
  id: string
  report: FailureReport
  logs: { name: string; text: string }[]
}
export interface AuditItem {
  at: string
  action: string
  success: boolean
  message: string
}
export type AccessMode = 'lan' | 'public'
export interface Security {
  access_mode: AccessMode
  applied_mode: AccessMode | null
  revision: string
  pending: boolean
  lan_only: boolean
  allowed_networks: string[]
  https: boolean
  session_idle_minutes: number
  session_absolute_hours: number
}
export type Page =
  | 'overview'
  | 'certificate'
  | 'renewal'
  | 'notifications'
  | 'failures'
  | 'audit'
  | 'security'
  | 'account'
export type SettingsPage = 'certificate' | 'renewal' | 'notifications'
