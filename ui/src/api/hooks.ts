import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from './client'
import type {
  PaginatedResponse,
  EventSummary,
  EventDetail,
  AlertSummary,
  AlertDetail,
  AlertPatch,
  RuleSummary,
  RuleDetail,
  RuleCreate,
  SourceSummary,
  SourceCreate,
  DashboardSummary,
  TimelineBucket,
  ComplianceReport,
  EventFilters,
  AlertFilters,
} from './types'

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
export function useDashboardSummary() {
  return useQuery<DashboardSummary>({
    queryKey: ['dashboard', 'summary'],
    queryFn: () => apiClient.get('/dashboard/summary').then((r) => r.data),
    refetchInterval: 30_000,
  })
}

export function useDashboardTimeline(bucket: '1m' | '5m' | '1h' = '5m') {
  return useQuery<TimelineBucket[]>({
    queryKey: ['dashboard', 'timeline', bucket],
    queryFn: () =>
      apiClient.get('/dashboard/timeline', { params: { bucket } }).then((r) => r.data),
    refetchInterval: 30_000,
  })
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------
export function useEvents(filters: EventFilters = {}) {
  return useQuery<PaginatedResponse<EventSummary>>({
    queryKey: ['events', filters],
    queryFn: () => apiClient.get('/events', { params: filters }).then((r) => r.data),
    placeholderData: (prev) => prev,
  })
}

export function useEvent(id: string) {
  return useQuery<EventDetail>({
    queryKey: ['events', id],
    queryFn: () => apiClient.get(`/events/${id}`).then((r) => r.data),
    enabled: !!id,
  })
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
export function useAlerts(filters: AlertFilters = {}) {
  return useQuery<PaginatedResponse<AlertSummary>>({
    queryKey: ['alerts', filters],
    queryFn: () => apiClient.get('/alerts', { params: filters }).then((r) => r.data),
    placeholderData: (prev) => prev,
    refetchInterval: 60_000,
  })
}

export function useAlert(id: string) {
  return useQuery<AlertDetail>({
    queryKey: ['alerts', id],
    queryFn: () => apiClient.get(`/alerts/${id}`).then((r) => r.data),
    enabled: !!id,
  })
}

export function usePatchAlert(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (patch: AlertPatch) =>
      apiClient.patch(`/alerts/${id}`, patch).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------
export function useRules() {
  return useQuery<PaginatedResponse<RuleSummary>>({
    queryKey: ['rules'],
    queryFn: () => apiClient.get('/rules').then((r) => r.data),
  })
}

export function useRule(id: string) {
  return useQuery<RuleDetail>({
    queryKey: ['rules', id],
    queryFn: () => apiClient.get(`/rules/${id}`).then((r) => r.data),
    enabled: !!id,
  })
}

export function useCreateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: RuleCreate) =>
      apiClient.post('/rules', body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useUpdateRule(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<RuleCreate>) =>
      apiClient.put(`/rules/${id}`, body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiClient.delete(`/rules/${id}`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------
export function useSources() {
  return useQuery<PaginatedResponse<SourceSummary>>({
    queryKey: ['sources'],
    queryFn: () => apiClient.get('/sources').then((r) => r.data),
    refetchInterval: 60_000,
  })
}

export function useCreateSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: SourceCreate) =>
      apiClient.post('/sources', body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sources'] }),
  })
}

export function useToggleSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, enable }: { id: string; enable: boolean }) =>
      apiClient
        .post(`/sources/${id}/${enable ? 'enable' : 'disable'}`)
        .then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sources'] }),
  })
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------
export function useComplianceReport(framework: 'hipaa' | 'pci_dss') {
  return useQuery<ComplianceReport>({
    queryKey: ['compliance', framework],
    queryFn: () =>
      apiClient.get('/compliance/report', { params: { framework } }).then((r) => r.data),
  })
}
