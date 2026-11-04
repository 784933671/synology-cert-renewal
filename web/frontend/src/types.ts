export interface Session {
  username: string
  csrf_token: string
  must_change_password: boolean
  email_verification_enabled?: boolean
  login_email_masked?: string
}
export interface LoginChallenge {
  verification_required: true
  email_masked: string
  expires_in: number
  resend_after: number
}
export interface ManualRenewal {
  request_id: string
  state: 'queued' | 'running' | 'succeeded' | 'failed' | 'expired'
  message: string
  requested_at: string
  completed_at?: string
  cooldown_until?: string
}
export interface Probe {
  host: string
  port: number
  server_name: string
}
export interface Schedule {
  enabled: boolean
  mode: 'hourly' | 'daily' | 'adaptive' | 'unsupported'
  interval_hours: number
  hour: number
  minute: number
  editable?: boolean
  active_mode?: 'daily' | 'hourly'
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
  manual_renewal?: ManualRenewal | null
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
  | 'health'
  | 'runs'
  | 'certificate'
  | 'renewal'
  | 'notifications'
  | 'failures'
  | 'audit'
  | 'security'
  | 'account'
export type SettingsPage = 'certificate' | 'renewal' | 'notifications'

export type HealthState = 'ok' | 'warning' | 'error' | 'unknown'
export interface MonitorDraft {
  enabled: boolean
  missed_runs: number
  grace_minutes: number
  expiry_hours: number
}
export interface MonitorSettings extends MonitorDraft {
  revision: string
  notification_enabled: boolean
  recipient: string
  interval_seconds: number
}
export interface HealthSnapshot {
  server_time: string
  timezone: string
  runtime: {
    checked_at: string | null
    stale: boolean
    stale_after_seconds: number
    components: { key: string; label: string; status: HealthState; message: string }[]
    container: {
      running: boolean | null
      health: string
      restart_count: number | null
      oom_killed: boolean | null
      started_at: string | null
      uptime_seconds: number | null
    }
  }
  supervisor: { status: string; stage: string; message: string; at: string | null } | null
  upgrade: { phase: string; label: string } | null
  events: { at: string; category: 'maintenance' | 'fault' | 'recovery' | 'info'; status: string; stage: string; message: string }[]
  monitor: {
    checked_at: string | null
    stale: boolean
    stale_after_seconds: number
    status: HealthState | 'disabled'
    task_enabled: boolean | null
    schedule_supported: boolean | null
    last_completed_at: string | null
    next_expected_at: string | null
    missed_runs: number | null
    certificate_remaining_seconds: number | null
    alerts: { code: string; label: string; since: string | null; message: string; notification_status: string }[]
    delivery: { enabled: boolean; recipient: string; last_error: string }
    settings: MonitorDraft & { version: 1 }
  }
}
export type RunState = 'running' | 'succeeded' | 'skipped' | 'failed' | 'interrupted'
export interface RunRecord {
  id: string
  kind: 'routine' | 'forced' | 'recovery' | 'check'
  status: RunState
  started_at: string
  finished_at: string | null
  duration_seconds: number | null
  domains: string[]
  certificate_id: string
  summary: string
  stages: {
    stage: string
    label: string
    status: RunState | 'unknown'
    started_at: string | null
    finished_at: string | null
    duration_seconds: number | null
    message: string
  }[]
}
export interface RunPage {
  items: RunRecord[]
  total: number
  offset: number
  limit: number
  warning?: string | null
}

export interface StepUpChallenge {
  challenge_id: string
  email_masked: string
  expires_in: number
  resend_after: number
  operation: string
}
export type SecurityDevice = 'desktop' | 'mobile' | 'tablet' | 'other' | 'unknown'
export interface LoginSession {
  id: string
  ip: string
  device: SecurityDevice
  created_at: string
  last_seen: string
  current: boolean
}
export interface SecurityAlert {
  id: string
  event_type: 'new_login' | 'login_failures' | 'security_change'
  at: string
  source_ip: string
  device: SecurityDevice
  status: 'pending' | 'sending' | 'sent' | 'failed'
  attempts: number
}
