// TypeScript types mirroring api/models/schemas.py

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AlertStatus = 'open' | 'acknowledged' | 'closed'
export type LogLevel = 'emergency' | 'alert' | 'critical' | 'error' | 'warning' | 'notice' | 'info' | 'debug'
export type Category = 'auth' | 'network' | 'endpoint' | 'system' | 'threat' | 'compliance'
export type SourceType = 'fortigate' | 'cisco_asa' | 'cisco_ios' | 'windows' | 'linux'
export type RuleType = 'threshold' | 'sequence' | 'absence' | 'blacklist' | 'anomaly'

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

// Events
export interface EventSummary {
  id: string
  received_at: string
  source_host: string
  source_type: SourceType | null
  log_level: LogLevel | null
  category: Category | null
  action: string | null
  src_ip: string | null
  dst_ip: string | null
  user_name: string | null
  message: string
  tags: string[]
}

export interface EventDetail extends EventSummary {
  event_time: string | null
  src_port: number | null
  dst_port: number | null
  protocol: string | null
  process_name: string | null
  event_id: string | null
  raw_message: string | null
  raw_hash: string | null
  geo_country: string | null
  geo_city: string | null
  alert_id: string | null
  ingest_node: string | null
  extra: Record<string, unknown> | null
}

// Alerts
export interface AlertSummary {
  id: string
  rule_id: string
  rule_name: string | null
  severity: Severity
  status: AlertStatus
  title: string
  description: string | null
  src_ip: string | null
  source_host: string | null
  first_seen: string
  last_seen: string
  event_count: number
  created_at: string
}

export interface AlertDetail extends AlertSummary {
  assigned_to: string | null
  extra: Record<string, unknown> | null
  linked_events: EventSummary[]
}

export interface AlertPatch {
  status?: AlertStatus
  assigned_to?: string
}

// Rules
export interface RuleSummary {
  id: string
  name: string
  rule_type: RuleType
  severity: Severity
  enabled: boolean
  created_at: string
}

export interface RuleDetail extends RuleSummary {
  description: string | null
  body: Record<string, unknown>
  updated_at: string
}

export interface RuleCreate {
  name: string
  description?: string
  rule_type: RuleType
  severity: Severity
  body: Record<string, unknown>
}

// Sources
export interface SourceSummary {
  id: string
  ip_address: string
  hostname: string | null
  source_type: SourceType
  label: string | null
  enabled: boolean
  last_seen: string | null
  event_rate_1m: number
}

export interface SourceCreate {
  ip_address: string
  hostname?: string
  source_type: SourceType
  label?: string
}

// Dashboard
export interface SeverityCount { severity: Severity; count: number }
export interface CategoryCount { category: Category; count: number }
export interface TopSource { source_host: string; event_count: number }
export interface TopRule { rule_name: string; alert_count: number }

export interface DashboardSummary {
  events_by_severity: SeverityCount[]
  events_by_category: CategoryCount[]
  top_sources: TopSource[]
  top_rules: TopRule[]
  open_alerts: number
  active_sources: number
  total_events_24h: number
}

export interface TimelineBucket {
  bucket: string
  count: number
}

// Compliance
export interface LogGap {
  source_host: string
  gap_start: string
  gap_end: string
  gap_minutes: number
}

export interface RetentionPosture {
  oldest_event: string | null
  total_events: number
  retention_days: number
  meets_hipaa: boolean
  meets_pci: boolean
}

export interface ComplianceReport {
  framework: string
  generated_at: string
  failed_logins_24h: number
  privilege_escalations_24h: number
  audit_log_clears_24h: number
  log_gaps: LogGap[]
  retention: RetentionPosture
  // PCI extras
  cardholder_env_events_24h?: number
  daily_review_gaps?: number
}

// Filter params for events list
export interface EventFilters {
  time_from?: string
  time_to?: string
  source?: string
  source_type?: SourceType
  category?: Category
  src_ip?: string
  dst_ip?: string
  user?: string
  log_level?: LogLevel
  q?: string
  sort_order?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

// Filter params for alerts list
export interface AlertFilters {
  status?: AlertStatus
  severity?: Severity
  rule_id?: string
  src_ip?: string
  page?: number
  page_size?: number
}
