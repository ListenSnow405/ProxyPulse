"use client"

import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  Activity, AlertTriangle, Check, ChevronRight, CircleDashed, Clock3, Gauge,
  Pencil, Plus, RefreshCw, Router, Settings2, ShieldCheck, Trash2, WifiOff, Zap,
} from "lucide-react"
import {
  CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer,
  Tooltip as RechartsTooltip, XAxis, YAxis,
} from "recharts"

import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const WINDOWS = [
  { label: "1 小时", value: 3600 },
  { label: "6 小时", value: 21600 },
  { label: "24 小时", value: 86400 },
  { label: "7 天", value: 604800 },
]

type NodeStatus = "unknown" | "healthy" | "suspect" | "down" | "recovering" | "stale"
type NodeStats = {
  checks: number; expected_checks: number; successes: number; timeouts: number; errors: number
  availability: number | null; coverage: number | null; average_ms: number | null; p95_ms: number | null
}
type ProxyNode = {
  id: number; name: string; scheme: "http" | "socks5"; host: string; port: number; enabled: boolean
  has_username: boolean; has_password: boolean; status: NodeStatus; consecutive_failures: number | null
  last_result_at: string | null; last_latency_ms: number | null; last_outcome: "success" | "timeout" | "error" | null
  last_error: string | null; current_incident_id: number | null; stats: NodeStats
}
type MonitorSettings = {
  interval_seconds: number; connect_timeout_seconds: number; request_timeout_seconds: number
  failure_threshold: number; recovery_threshold: number; retention_days: number; targets: string[]
}
type SeriesPoint = {
  timestamp: string; latency_ms: number | null; min_ms: number | null; max_ms: number | null
  outcome: "success" | "timeout" | "error"; timeout_count: number; error_count: number; sample_count: number
  samplingGap?: boolean
}
type Incident = {
  id: number; node_id: number; started_at: string; confirmed_at: string; ended_at: string | null
  recovery_confirmed_at: string | null; last_failure_at: string; category: "timeout" | "error"
  timeout_phase: string | null; failure_count: number; last_error: string | null; status: "open" | "closed"
  end_confirmed: number; close_reason: string | null
}
type SamplingGap = { started_at: string; ended_at: string; ongoing: boolean }
type TargetResult = {
  target: string; outcome: "success" | "timeout" | "error"; total_ms: number | null; tcp_ms: number | null
  proxy_ms: number | null; tls_ms: number | null; ttfb_ms: number | null; http_status: number | null
  timeout_phase: string | null; error_type: string | null; completed_at: string
}
type Dashboard = {
  generated_at: string; selected_node_id: number | null; settings: MonitorSettings; nodes: ProxyNode[]
  window_started_at: string; window_ended_at: string; series: SeriesPoint[]; incidents: Incident[]
  sampling_gaps: SamplingGap[]; target_results: TargetResult[]
  monitor: {
    running: boolean; cycle_running: boolean; started_at: string; last_cycle_started_at: string | null
    last_cycle_completed_at: string | null; last_cycle_error: string | null
  }
}
type NodeForm = {
  name: string; scheme: "http" | "socks5"; host: string; port: string
  username: string; password: string; enabled: boolean; clear_credentials: boolean
}

const EMPTY_NODE: NodeForm = {
  name: "", scheme: "http", host: "127.0.0.1", port: "7890", username: "", password: "", enabled: true,
  clear_credentials: false,
}

function apiBase() {
  if (typeof window !== "undefined" && window.location.port === "5173") return "http://127.0.0.1:8765"
  return ""
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set("Content-Type", "application/json")
  headers.set("X-ProxyPulse-Request", "1")
  const response = await fetch(`${apiBase()}${path}`, {
    ...init,
    headers,
  })
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => ({ error: "请求失败" }))
    const message = payload && typeof payload === "object" && "error" in payload
      ? String((payload as { error: unknown }).error)
      : `请求失败 (${response.status})`
    throw new Error(message)
  }
  if (response.status === 204) return undefined as T
  return response.json()
}

function formatLatency(value: number | null | undefined) {
  if (value == null) return "—"
  return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${Math.round(value)} ms`
}

function targetLabel(value: string) {
  try { return new URL(value).host }
  catch { return value }
}

function formatTime(value: string | null | undefined, seconds = false) {
  if (!value) return "—"
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
    second: seconds ? "2-digit" : undefined, hour12: false,
  }).format(new Date(value))
}

function durationMs(start: string, end: string | null, now: string) {
  return Math.max(0, new Date(end || now).getTime() - new Date(start).getTime())
}

function formatMilliseconds(milliseconds: number) {
  const seconds = Math.round(milliseconds / 1000)
  if (seconds < 60) return `${seconds} 秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor((seconds % 3600) / 60)} 分`
}

const STATUS_META: Record<NodeStatus, { label: string; className: string }> = {
  healthy: { label: "正常", className: "status-good" },
  suspect: { label: "波动", className: "status-warn" },
  recovering: { label: "恢复确认中", className: "status-warn" },
  down: { label: "不可用", className: "status-bad" },
  stale: { label: "数据中断", className: "status-muted" },
  unknown: { label: "等待探测", className: "status-muted" },
}
const PHASE_NAMES: Record<string, string> = {
  connect: "连接代理", proxy_handshake: "代理握手", tls: "TLS 握手", first_byte: "等待首字节", total: "整体请求",
}

function StatusPill({ status, enabled = true }: { status: NodeStatus; enabled?: boolean }) {
  const meta = enabled ? (STATUS_META[status] || STATUS_META.unknown) : { label: "已停用", className: "status-muted" }
  return <span className={`status-pill ${meta.className}`}><span className="status-dot" />{meta.label}</span>
}

function MetricCard({ label, value, detail, icon: Icon, tone = "cyan" }: {
  label: string; value: string; detail: string; icon: typeof Activity; tone?: "cyan" | "green" | "amber" | "red"
}) {
  return <Card className={`metric-card metric-${tone}`}>
    <div className="metric-icon"><Icon aria-hidden="true" /></div>
    <div><p className="metric-label">{label}</p><p className="metric-value">{value}</p><p className="metric-detail">{detail}</p></div>
  </Card>
}

function LatencyTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: SeriesPoint & { time: number } }> }) {
  const point = payload?.[0]?.payload
  if (!active || !point) return null
  return <div className="chart-tooltip">
    <p>{formatTime(point.timestamp, true)}</p>
    <strong>{point.samplingGap ? "未采样" : point.latency_ms == null ? (point.outcome === "timeout" ? "Timeout" : "请求错误") : formatLatency(point.latency_ms)}</strong>
    {point.sample_count > 1 && <span>{point.sample_count} 次采样聚合</span>}
    {(point.timeout_count > 0 || point.error_count > 0) && <span>{point.timeout_count} 次超时 · {point.error_count} 次错误</span>}
  </div>
}

function NodeDialog({ open, node, saving, onOpenChange, onSave }: {
  open: boolean; node: ProxyNode | null; saving: boolean; onOpenChange: (open: boolean) => void
  onSave: (form: NodeForm) => Promise<void>
}) {
  const [form, setForm] = useState<NodeForm>(() => node ? {
    name: node.name, scheme: node.scheme, host: node.host, port: String(node.port),
    username: "", password: "", enabled: node.enabled, clear_credentials: false,
  } : EMPTY_NODE)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null)
    if (!form.name.trim() || !form.host.trim() || !form.port) { setError("请填写节点名称、主机和端口"); return }
    try { await onSave(form) } catch (reason) { setError(reason instanceof Error ? reason.message : "保存失败") }
  }

  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent className="border-white/10 bg-[#0b1724] text-[#ecf8ff] sm:max-w-[560px]">
      <form onSubmit={submit}>
        <DialogHeader><DialogTitle>{node ? "编辑代理节点" : "添加代理节点"}</DialogTitle>
          <DialogDescription className="text-slate-400">填写可直接连接的本地或远程 HTTP CONNECT / SOCKS5 地址。</DialogDescription>
        </DialogHeader>
        <div className="mt-6 grid gap-5">
          <div className="grid gap-2"><Label htmlFor="node-name">节点名称</Label><Input id="node-name" autoFocus value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="例如：香港 01" /></div>
          <div className="grid grid-cols-[1fr_1.6fr_0.8fr] gap-3 max-sm:grid-cols-1">
            <div className="grid gap-2"><Label>协议</Label>
              <Select value={form.scheme} onValueChange={(value: "http" | "socks5") => setForm({ ...form, scheme: value })}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="http">HTTP CONNECT</SelectItem><SelectItem value="socks5">SOCKS5</SelectItem></SelectContent>
              </Select>
            </div>
            <div className="grid gap-2"><Label htmlFor="node-host">主机 / IP</Label><Input id="node-host" value={form.host} onChange={(event) => setForm({ ...form, host: event.target.value })} placeholder="127.0.0.1" /></div>
            <div className="grid gap-2"><Label htmlFor="node-port">端口</Label><Input id="node-port" inputMode="numeric" value={form.port} onChange={(event) => setForm({ ...form, port: event.target.value })} placeholder="7890" /></div>
          </div>
          <div className="grid grid-cols-2 gap-3 max-sm:grid-cols-1">
            <div className="grid gap-2"><Label htmlFor="node-user">用户名（可选）</Label><Input id="node-user" autoComplete="off" disabled={form.clear_credentials} value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} placeholder={node?.has_username ? "留空则保留原用户名" : "无需认证可留空"} /></div>
            <div className="grid gap-2"><Label htmlFor="node-pass">密码（可选）</Label><Input id="node-pass" type="password" autoComplete="new-password" disabled={form.clear_credentials} value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} placeholder={node?.has_password ? "留空则保留原密码" : "无需认证可留空"} /></div>
          </div>
          {node && (node.has_username || node.has_password) && <div className="flex items-center justify-between rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3">
            <div><Label htmlFor="clear-credentials" className="text-sm">清除已保存凭据</Label><p className="mt-1 text-xs text-slate-400">保存后删除该节点现有的用户名和密码。</p></div>
            <Switch id="clear-credentials" checked={form.clear_credentials} onCheckedChange={(clear_credentials) => setForm({ ...form, clear_credentials, username: clear_credentials ? "" : form.username, password: clear_credentials ? "" : form.password })} />
          </div>}
          <div className="flex items-center justify-between rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3">
            <div><Label htmlFor="node-enabled" className="text-sm">启用定时探测</Label><p className="mt-1 text-xs text-slate-500">关闭后保留历史数据，不再产生新采样。</p></div>
            <Switch id="node-enabled" checked={form.enabled} onCheckedChange={(enabled) => setForm({ ...form, enabled })} />
          </div>
          {error && <p role="alert" className="form-error">{error}</p>}
        </div>
        <DialogFooter className="mt-6"><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
          <Button type="submit" disabled={saving} className="bg-cyan-400 text-slate-950 hover:bg-cyan-300">{saving && <RefreshCw className="animate-spin" />}{node ? "保存修改" : "添加并开始监测"}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
}

function SettingsDialog({ open, settings, saving, onOpenChange, onSave }: {
  open: boolean; settings: MonitorSettings; saving: boolean; onOpenChange: (open: boolean) => void
  onSave: (settings: MonitorSettings) => Promise<void>
}) {
  const [form, setForm] = useState<MonitorSettings>(() => settings)
  const [targets, setTargets] = useState(() => settings.targets.join("\n"))
  const [error, setError] = useState<string | null>(null)
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null)
    try { await onSave({ ...form, targets: targets.split("\n").map((item) => item.trim()).filter(Boolean) }) }
    catch (reason) { setError(reason instanceof Error ? reason.message : "保存失败") }
  }
  const numberField = (key: keyof MonitorSettings, label: string, min: number, max: number, step = 1) => <div className="grid gap-2">
    <Label htmlFor={`setting-${key}`}>{label}</Label><Input id={`setting-${key}`} type="number" min={min} max={max} step={step} value={String(form[key])} onChange={(event) => setForm({ ...form, [key]: Number(event.target.value) })} />
  </div>
  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent className="border-white/10 bg-[#0b1724] text-[#ecf8ff] sm:max-w-[620px]"><form onSubmit={submit}>
      <DialogHeader><DialogTitle>监测设置</DialogTitle><DialogDescription className="text-slate-400">参数修改后会从下一轮探测开始生效。</DialogDescription></DialogHeader>
      <div className="mt-6 grid grid-cols-3 gap-4 max-sm:grid-cols-2">
        {numberField("interval_seconds", "探测间隔（秒）", 2, 3600)}
        {numberField("connect_timeout_seconds", "连接超时（秒）", 0.2, 60, 0.1)}
        {numberField("request_timeout_seconds", "整体超时（秒）", 0.5, 120, 0.1)}
        {numberField("failure_threshold", "故障确认次数", 1, 20)}
        {numberField("recovery_threshold", "恢复确认次数", 1, 20)}
        {numberField("retention_days", "数据保留（天）", 1, 3650)}
      </div>
      <div className="mt-5 grid gap-2"><Label htmlFor="setting-targets">测试目标（每行一个，最多 5 个）</Label>
        <textarea id="setting-targets" className="min-h-28 rounded-md border border-input bg-transparent px-3 py-2 font-mono text-sm outline-none focus:border-cyan-400/70 focus:ring-2 focus:ring-cyan-400/15" value={targets} onChange={(event) => setTargets(event.target.value)} />
        <p className="text-xs text-slate-500">任一目标成功即可证明节点可用，避免单个测试站故障造成误报。</p>
      </div>
      {error && <p role="alert" className="form-error mt-4">{error}</p>}
      <DialogFooter className="mt-6"><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button><Button type="submit" disabled={saving} className="bg-cyan-400 text-slate-950 hover:bg-cyan-300">{saving && <RefreshCw className="animate-spin" />}保存设置</Button></DialogFooter>
    </form></DialogContent>
  </Dialog>
}

export default function Home() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null)
  const [windowSeconds, setWindowSeconds] = useState(86400)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [nodeDialogOpen, setNodeDialogOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [editingNode, setEditingNode] = useState<ProxyNode | null>(null)
  const [saving, setSaving] = useState(false)
  const [probingNodeId, setProbingNodeId] = useState<number | null>(null)
  const [deleteNode, setDeleteNode] = useState<ProxyNode | null>(null)
  const requestSequence = useRef(0)

  const refresh = useCallback(async (quiet = false) => {
    const requestId = ++requestSequence.current
    if (!quiet) setRefreshing(true)
    try {
      const query = new URLSearchParams({ window: String(windowSeconds), points: "720" })
      if (selectedNodeId != null) query.set("node_id", String(selectedNodeId))
      const data = await api<Dashboard>(`/api/dashboard?${query}`)
      if (requestId !== requestSequence.current) return
      setDashboard(data); setError(null)
      if (selectedNodeId == null && data.selected_node_id != null) setSelectedNodeId(data.selected_node_id)
    } catch (reason) {
      if (requestId === requestSequence.current) setError(reason instanceof Error ? reason.message : "无法连接监测服务")
    } finally {
      if (requestId === requestSequence.current) { setLoading(false); setRefreshing(false) }
    }
  }, [selectedNodeId, windowSeconds])

  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0)
    return () => window.clearTimeout(timer)
  }, [refresh])
  useEffect(() => {
    const context = document.modelContext
    if (!context?.registerTool) return
    const lifecycle = new AbortController()
    const register = (tool: WebMcpTool) => {
      try { void Promise.resolve(context.registerTool(tool, { signal: lifecycle.signal })).catch(() => undefined) }
      catch { /* WebMCP is optional in browsers that only partially expose the proposal. */ }
    }
    register({
      name: "list_proxy_nodes",
      title: "查看代理节点",
      description: "读取 ProxyPulse 中已配置的代理节点及其当前状态，不包含任何凭据。",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      async execute() {
        const result = await api<{ nodes: ProxyNode[] }>("/api/nodes")
        return { nodes: result.nodes.map(({ id, name, scheme, host, port, enabled, status }) => ({ id, name, scheme, host, port, enabled, status })) }
      },
    })
    register({
      name: "create_proxy_node",
      title: "添加代理节点",
      description: "向本机 ProxyPulse 添加一个 HTTP CONNECT 或 SOCKS5 节点，并开始定时探测。",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", minLength: 1, maxLength: 80 },
          scheme: { type: "string", enum: ["http", "socks5"] },
          host: { type: "string", minLength: 1 },
          port: { type: "integer", minimum: 1, maximum: 65535 },
          username: { type: "string" },
          password: { type: "string" },
        },
        required: ["name", "scheme", "host", "port"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      async execute(input) {
        if (!input || typeof input !== "object") throw new Error("节点参数必须是对象")
        const value = input as Record<string, unknown>
        if (typeof value.name !== "string" || typeof value.host !== "string" || !["http", "socks5"].includes(String(value.scheme)) || !Number.isInteger(value.port)) throw new Error("节点名称、协议、主机或端口格式不正确")
        const response = await api<{ node: ProxyNode }>("/api/nodes", { method: "POST", body: JSON.stringify({ ...value, enabled: true }) })
        setSelectedNodeId(response.node.id)
        await refresh(true)
        return { id: response.node.id, name: response.node.name, monitoring: true }
      },
    })
    register({
      name: "probe_proxy_node",
      title: "立即探测代理节点",
      description: "立即对一个已配置节点执行完整探测，并返回成功、Timeout 或错误结果。",
      inputSchema: {
        type: "object",
        properties: { nodeId: { type: "integer", minimum: 1 } },
        required: ["nodeId"], additionalProperties: false,
      },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      async execute(input) {
        if (!input || typeof input !== "object" || !Number.isInteger((input as { nodeId?: unknown }).nodeId)) throw new Error("nodeId 必须是正整数")
        const nodeId = Number((input as { nodeId: number }).nodeId)
        const response = await api<{ probe: { aggregate?: { outcome: string; latency_ms?: number | null; timeout_phase?: string | null } } }>(`/api/nodes/${nodeId}/probe`, { method: "POST", body: "{}" })
        await refresh(true)
        return response.probe?.aggregate || { outcome: "skipped" }
      },
    })
    return () => lifecycle.abort()
  }, [refresh])
  useEffect(() => {
    if (!autoRefresh) return
    const timer = window.setInterval(() => void refresh(true), 5000)
    return () => window.clearInterval(timer)
  }, [autoRefresh, refresh])
  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(null), 3500)
    return () => window.clearTimeout(timer)
  }, [notice])

  const selectedNode = dashboard?.nodes.find((node) => node.id === selectedNodeId) || null
  const detailsMatch = dashboard?.selected_node_id === selectedNodeId
  const detailIncidents = useMemo(() => detailsMatch ? dashboard?.incidents || [] : [], [dashboard?.incidents, detailsMatch])
  const detailTargets = useMemo(() => detailsMatch ? dashboard?.target_results || [] : [], [dashboard?.target_results, detailsMatch])
  const detailGaps = useMemo(() => detailsMatch ? dashboard?.sampling_gaps || [] : [], [dashboard?.sampling_gaps, detailsMatch])
  const orderedNodes = useMemo(() => {
    const priority: Record<NodeStatus, number> = { down: 0, suspect: 1, recovering: 2, stale: 3, unknown: 4, healthy: 5 }
    return [...(dashboard?.nodes || [])].sort((a, b) => priority[a.status] - priority[b.status] || a.name.localeCompare(b.name, "zh-CN"))
  }, [dashboard?.nodes])
  const overview = useMemo(() => {
    const enabled = (dashboard?.nodes || []).filter((node) => node.enabled)
    const healthy = enabled.filter((node) => node.status === "healthy").length
    const checks = enabled.reduce((sum, node) => sum + node.stats.checks, 0)
    const expectedChecks = enabled.reduce((sum, node) => sum + node.stats.expected_checks, 0)
    const successes = enabled.reduce((sum, node) => sum + node.stats.successes, 0)
    const timeoutIncidents = detailIncidents.filter((incident) => incident.category === "timeout")
    const rangeEnd = dashboard ? new Date(dashboard.window_ended_at).getTime() : 0
    const rangeStart = dashboard ? new Date(dashboard.window_started_at).getTime() : rangeEnd - windowSeconds * 1000
    const timeoutMs = timeoutIncidents.reduce((sum, incident) => {
      const start = Math.max(rangeStart, new Date(incident.started_at).getTime())
      const end = Math.min(rangeEnd, new Date(incident.ended_at || dashboard!.window_ended_at).getTime())
      return sum + Math.max(0, end - start)
    }, 0)
    return {
      healthy, enabled: enabled.length, checks,
      availability: checks ? successes / checks * 100 : null,
      coverage: expectedChecks ? Math.min(100, checks / expectedChecks * 100) : null,
      timeoutIncidents, timeoutMs,
    }
  }, [dashboard, detailIncidents, windowSeconds])
  const chartData = useMemo(() => {
    const points = (detailsMatch ? dashboard?.series || [] : []).map((point) => ({
      ...point, time: new Date(point.timestamp).getTime(), samplingGap: false,
    }))
    if (points.length < 2) return points
    const first = points[0].time
    const last = points[points.length - 1].time
    const breaks = detailGaps.flatMap((gap) => {
      const start = new Date(gap.started_at).getTime()
      const end = new Date(gap.ended_at).getTime()
      const time = start + Math.max(1, (end - start) / 2)
      if (time <= first || time >= last) return []
      return [{
        timestamp: new Date(time).toISOString(), time, latency_ms: null, min_ms: null, max_ms: null,
        outcome: "error" as const, timeout_count: 0, error_count: 0, sample_count: 0, samplingGap: true,
      }]
    })
    return [...points, ...breaks].sort((a, b) => a.time - b.time)
  }, [dashboard?.series, detailGaps, detailsMatch])

  async function saveNode(form: NodeForm) {
    setSaving(true)
    try {
      const body = {
        name: form.name.trim(), scheme: form.scheme, host: form.host.trim(), port: Number(form.port),
        username: form.username || undefined, password: form.password || undefined, enabled: form.enabled,
        clear_credentials: form.clear_credentials,
      }
      if (editingNode) {
        await api(`/api/nodes/${editingNode.id}`, { method: "PUT", body: JSON.stringify(body) }); setNotice(`已更新 ${form.name}`)
      } else {
        const response = await api<{ node: ProxyNode }>("/api/nodes", { method: "POST", body: JSON.stringify(body) })
        setSelectedNodeId(response.node.id); setNotice(`已添加 ${form.name}，正在进行首次探测`)
      }
      setNodeDialogOpen(false); setEditingNode(null); await refresh()
    } finally { setSaving(false) }
  }
  async function saveSettings(settings: MonitorSettings) {
    setSaving(true)
    try { await api("/api/settings", { method: "PUT", body: JSON.stringify(settings) }); setSettingsOpen(false); setNotice("监测设置已更新"); await refresh() }
    finally { setSaving(false) }
  }
  async function probeNow(node: ProxyNode) {
    setProbingNodeId(node.id)
    try {
      const result = await api<{ probe: { aggregate?: { outcome: string } } }>(`/api/nodes/${node.id}/probe`, { method: "POST", body: "{}" })
      setNotice(result.probe?.aggregate?.outcome === "success" ? `${node.name} 探测成功` : `${node.name} 探测完成，请查看结果`); await refresh()
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "立即探测失败") }
    finally { setProbingNodeId(null) }
  }
  async function confirmDelete() {
    if (!deleteNode) return
    try {
      await api(`/api/nodes/${deleteNode.id}`, { method: "DELETE" })
      if (selectedNodeId === deleteNode.id) setSelectedNodeId(null)
      setNotice(`已删除 ${deleteNode.name} 及其历史数据`); setDeleteNode(null); await refresh()
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "删除失败") }
  }

  return <main className="min-h-screen bg-grid text-slate-100">
    <header className="topbar">
      <div className="brand-mark" aria-hidden="true"><Activity /></div>
      <div className="min-w-0"><h1>ProxyPulse</h1><p>个人代理节点监测</p></div>
      <div className="ml-auto flex items-center gap-2 max-sm:gap-1">
        <span className={`service-state ${dashboard?.monitor.running ? "online" : "offline"}`}><span />{dashboard?.monitor.running ? "监测中" : "服务离线"}</span>
        <Button size="sm" variant="ghost" className="top-action" onClick={() => setSettingsOpen(true)} aria-label="监测设置"><Settings2 /></Button>
        <Button size="sm" className="add-button" onClick={() => { setEditingNode(null); setNodeDialogOpen(true) }}><Plus /><span>添加节点</span></Button>
      </div>
    </header>

    <div className="workspace">
      {error && <div className="connection-banner" role="alert"><WifiOff /><div><strong>无法连接本地监测服务</strong><span>{error}。请确认已运行启动脚本。</span></div><Button size="sm" variant="outline" onClick={() => void refresh()}>重试</Button></div>}
      <section className="overview-grid" aria-label="监测概览">
        <MetricCard label="在线节点" value={`${overview.healthy} / ${overview.enabled}`} detail={overview.enabled ? "当前确认正常" : "尚未添加节点"} icon={ShieldCheck} tone="green" />
        <MetricCard label="成功采样率" value={overview.availability == null ? "—" : `${overview.availability.toFixed(2)}%`} detail={`采样覆盖 ${overview.coverage == null ? "—" : `${overview.coverage.toFixed(1)}%`} · ${overview.checks} 次`} icon={Gauge} tone="cyan" />
        <MetricCard label="所选节点 P95" value={formatLatency(selectedNode?.stats.p95_ms)} detail={selectedNode?.name || "选择节点后显示"} icon={Zap} tone="amber" />
        <MetricCard label="所选节点 Timeout" value={String(overview.timeoutIncidents.length)} detail={overview.timeoutMs ? `累计 ${formatMilliseconds(overview.timeoutMs)}` : "当前范围未发现"} icon={AlertTriangle} tone="red" />
      </section>

      <section className="monitor-layout">
        <Card className="node-panel">
          <div className="panel-heading"><div><p className="eyebrow">NODES</p><h2>代理节点</h2></div><span>{dashboard?.nodes.length || 0}</span></div>
          <div className="node-list">
            {loading && !dashboard && [0, 1, 2].map((item) => <div className="node-skeleton" key={item} />)}
            {!loading && dashboard?.nodes.length === 0 && <div className="empty-node"><div><Router /></div><h3>添加第一个代理节点</h3><p>配置一个 HTTP CONNECT 或 SOCKS5 地址后，延迟曲线会从首次探测开始生成。</p><Button onClick={() => { setEditingNode(null); setNodeDialogOpen(true) }}><Plus />添加节点</Button></div>}
            {orderedNodes.map((node) => <button type="button" key={node.id} className={`node-row ${selectedNodeId === node.id ? "selected" : ""}`} aria-pressed={selectedNodeId === node.id} onClick={() => setSelectedNodeId(node.id)}>
              <span className={`node-orb ${node.enabled ? (STATUS_META[node.status]?.className || "status-muted") : "status-muted"}`}><Router /></span>
              <span className="node-copy"><span className="node-name-line"><strong>{node.name}</strong><StatusPill status={node.status} enabled={node.enabled} /></span>
                <span className="node-endpoint">{node.scheme.toUpperCase()} · {node.host}:{node.port}</span>
                <span className="node-stats"><b>{formatLatency(node.last_latency_ms)}</b><span>P95 {formatLatency(node.stats.p95_ms)}</span><span>{node.stats.availability == null ? "—" : `${node.stats.availability.toFixed(1)}%`}</span></span>
              </span><ChevronRight className="row-chevron" />
            </button>)}
          </div>
        </Card>

        <div className="detail-stack">
          <Card className="chart-panel">
            <div className="chart-heading"><div>
              <div className="flex items-center gap-2"><StatusPill status={selectedNode?.status || "unknown"} enabled={selectedNode?.enabled ?? true} /><span className="last-sample">最后采样 {formatTime(selectedNode?.last_result_at, true)}</span></div>
              <h2>{selectedNode?.name || "延迟趋势"}</h2>{selectedNode && <p>{selectedNode.scheme.toUpperCase()} · {selectedNode.host}:{selectedNode.port}</p>}
            </div><div className="chart-actions">
              <div className="range-control" aria-label="时间范围">{WINDOWS.map((item) => <button type="button" key={item.value} className={windowSeconds === item.value ? "active" : ""} aria-pressed={windowSeconds === item.value} onClick={() => setWindowSeconds(item.value)}>{item.label}</button>)}</div>
              <button type="button" className={`icon-action ${autoRefresh ? "active" : ""}`} aria-pressed={autoRefresh} aria-label={autoRefresh ? "关闭自动刷新" : "开启自动刷新"} onClick={() => setAutoRefresh((value) => !value)} title={autoRefresh ? "自动刷新已开启" : "自动刷新已关闭"}><Clock3 /></button>
              <button type="button" className="icon-action" onClick={() => void refresh()} title="刷新" disabled={refreshing}><RefreshCw className={refreshing ? "animate-spin" : ""} /></button>
              {selectedNode && <button type="button" className="icon-action" onClick={() => { setEditingNode(selectedNode); setNodeDialogOpen(true) }} title="编辑节点"><Pencil /></button>}
            </div></div>

            {!selectedNode ? <div className="chart-empty"><CircleDashed /><p>{dashboard?.nodes.length ? "请选择一个节点查看趋势" : "添加节点后，这里会显示延迟曲线和 Timeout 时间段"}</p></div>
            : !detailsMatch ? <div className="chart-empty"><RefreshCw className="animate-spin" /><p>正在加载 {selectedNode.name} 的监测数据…</p></div>
            : chartData.length === 0 ? <div className="chart-empty"><Activity /><p>正在等待首次探测结果…</p><Button variant="outline" onClick={() => void probeNow(selectedNode)} disabled={probingNodeId === selectedNode.id}>{probingNodeId === selectedNode.id && <RefreshCw className="animate-spin" />}立即测试</Button></div>
            : <>
              <p className="sr-only">{selectedNode.name} 在当前时间范围有 {chartData.length} 个数据点、{detailIncidents.filter((item) => item.category === "timeout").length} 个 Timeout 区间和 {detailGaps.length} 个未采样区间。</p>
              <div className="latency-chart" role="img" aria-label={`${selectedNode.name} 延迟曲线`}><ResponsiveContainer width="100%" height="100%"><LineChart data={chartData} margin={{ top: 22, right: 18, bottom: 4, left: 0 }}>
                <defs><linearGradient id="lineGlow" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="#22d3ee" /><stop offset="1" stopColor="#60a5fa" /></linearGradient><pattern id="timeoutPattern" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="4" height="8" fill="rgba(251,113,133,.11)" /></pattern><pattern id="errorPattern" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="4" height="8" fill="rgba(251,146,60,.1)" /></pattern></defs>
                <CartesianGrid strokeDasharray="3 7" stroke="rgba(148,163,184,.11)" vertical={false} />
                <XAxis dataKey="time" type="number" scale="time" domain={[new Date(dashboard!.window_started_at).getTime(), new Date(dashboard!.window_ended_at).getTime()]} tickFormatter={(value) => formatTime(new Date(value).toISOString())} stroke="rgba(148,163,184,.45)" tickLine={false} axisLine={false} minTickGap={48} />
                <YAxis width={54} tickFormatter={(value) => `${Math.round(value)}ms`} stroke="rgba(148,163,184,.45)" tickLine={false} axisLine={false} />
                {detailGaps.map((gap, index) => <ReferenceArea key={`gap-${index}`} x1={new Date(gap.started_at).getTime()} x2={new Date(gap.ended_at).getTime()} fill="#64748b" fillOpacity={0.08} stroke="none" />)}
                {detailIncidents.map((incident) => <ReferenceArea key={incident.id} x1={new Date(incident.started_at).getTime()} x2={new Date(incident.ended_at || dashboard!.window_ended_at).getTime()} fill={incident.status === "open" ? (incident.category === "timeout" ? "url(#timeoutPattern)" : "url(#errorPattern)") : incident.category === "timeout" ? "#fb7185" : "#fb923c"} fillOpacity={incident.status === "open" ? 1 : 0.09} stroke={incident.category === "timeout" ? "#fb7185" : "#fb923c"} strokeOpacity={0.25} />)}
                <RechartsTooltip content={<LatencyTooltip />} cursor={{ stroke: "rgba(103,232,249,.3)", strokeWidth: 1 }} />
                <Line dataKey="latency_ms" type="monotone" stroke="url(#lineGlow)" strokeWidth={2.4} dot={false} activeDot={{ r: 4, fill: "#67e8f9", stroke: "#0b1724", strokeWidth: 2 }} connectNulls={false} isAnimationActive={false} />
              </LineChart></ResponsiveContainer></div>
              <div className="timeline-strip" aria-label="Timeout 状态条"><span className="strip-label">状态</span><div className="strip-track">
                {detailGaps.map((gap, index) => {
                  const rangeStart = new Date(dashboard!.window_started_at).getTime()
                  const rangeSize = new Date(dashboard!.window_ended_at).getTime() - rangeStart
                  const start = Math.max(new Date(gap.started_at).getTime(), rangeStart)
                  const end = Math.min(new Date(gap.ended_at).getTime(), rangeStart + rangeSize)
                  return <span key={`gap-${index}`} className="strip-gap" style={{ left: `${Math.max(0, (start - rangeStart) / rangeSize * 100)}%`, width: `${Math.max(0.3, (end - start) / rangeSize * 100)}%` }} title="此时段未采样" />
                })}
                {detailIncidents.map((incident) => {
                  const rangeStart = new Date(dashboard!.window_started_at).getTime()
                  const rangeSize = new Date(dashboard!.window_ended_at).getTime() - rangeStart
                  const start = Math.max(new Date(incident.started_at).getTime(), rangeStart)
                  const end = Math.min(new Date(incident.ended_at || dashboard!.window_ended_at).getTime(), rangeStart + rangeSize)
                  return <span key={incident.id} className={`strip-incident ${incident.category} ${incident.status === "open" ? "ongoing" : ""}`} style={{ left: `${Math.max(0, (start - rangeStart) / rangeSize * 100)}%`, width: `${Math.max(0.3, (end - start) / rangeSize * 100)}%` }} title={`${incident.category === "timeout" ? "Timeout" : "错误"} ${formatMilliseconds(Math.max(0, end - start))}`} />
                })}
              </div><div className="strip-legend"><span><i className="bad" />Timeout</span><span><i className="error" />错误</span><span><i className="gap" />未采样</span></div></div>
            </>}
          </Card>

          {selectedNode && dashboard && detailsMatch && <div className="lower-grid">
            <Card className="target-panel"><div className="section-title"><div><p className="eyebrow">LATEST PROBE</p><h3>分阶段耗时</h3></div><Button size="sm" variant="outline" onClick={() => void probeNow(selectedNode)} disabled={probingNodeId === selectedNode.id}>{probingNodeId === selectedNode.id ? <RefreshCw className="animate-spin" /> : <Zap />}立即测试</Button></div>
              {detailTargets.length ? <Table><TableHeader><TableRow><TableHead>测试目标</TableHead><TableHead>结果</TableHead><TableHead className="text-right">连接</TableHead><TableHead className="text-right">代理握手</TableHead><TableHead className="text-right">TLS</TableHead><TableHead className="text-right">TTFB</TableHead><TableHead className="text-right">总耗时</TableHead></TableRow></TableHeader>
                <TableBody>{detailTargets.map((result) => <TableRow key={result.target}><TableCell className="max-w-[220px] truncate font-mono text-xs" title={result.target}>{targetLabel(result.target)}</TableCell><TableCell><span className={`result-mark ${result.outcome}`}><span />{result.outcome === "success" ? `HTTP ${result.http_status}` : result.outcome === "timeout" ? "Timeout" : "错误"}</span></TableCell><TableCell className="text-right tabular-nums">{formatLatency(result.tcp_ms)}</TableCell><TableCell className="text-right tabular-nums">{formatLatency(result.proxy_ms)}</TableCell><TableCell className="text-right tabular-nums">{formatLatency(result.tls_ms)}</TableCell><TableCell className="text-right tabular-nums">{formatLatency(result.ttfb_ms)}</TableCell><TableCell className="text-right font-medium tabular-nums">{formatLatency(result.total_ms)}</TableCell></TableRow>)}</TableBody>
              </Table> : <p className="section-empty">暂无探测明细</p>}
            </Card>
            <Card className="incident-panel"><div className="section-title"><div><p className="eyebrow">INCIDENTS</p><h3>故障时间段</h3></div><span className="incident-count">{detailIncidents.length}</span></div><div className="incident-list">
              {detailIncidents.length === 0 && <div className="all-clear"><Check /><div><strong>当前时段没有故障</strong><span>未识别到连续 Timeout 或错误区间</span></div></div>}
              {[...detailIncidents].reverse().map((incident) => <article className="incident-row" key={incident.id}><span className={`incident-rail ${incident.category}`} /><div className="incident-copy"><div><strong>{incident.category === "timeout" ? "Timeout" : "连接错误"}</strong>{incident.status === "open" && <span className="ongoing-label">持续中</span>}{incident.status === "closed" && !incident.end_confirmed && <span className="uncertain-label">结束未确认</span>}</div><p>{formatTime(incident.started_at, true)} → {incident.ended_at ? formatTime(incident.ended_at, true) : "现在"}</p><span>{PHASE_NAMES[incident.timeout_phase || ""] || incident.timeout_phase || "链路不可用"} · 连续失败 {incident.failure_count} 次</span></div><strong className="incident-duration">{formatMilliseconds(durationMs(incident.started_at, incident.ended_at, dashboard.window_ended_at))}</strong></article>)}
            </div></Card>
          </div>}
          {selectedNode && <div className="node-footer-actions"><button type="button" onClick={() => { setEditingNode(selectedNode); setNodeDialogOpen(true) }}><Pencil />编辑节点</button><button type="button" className="danger" onClick={() => setDeleteNode(selectedNode)}><Trash2 />删除节点及历史数据</button></div>}
        </div>
      </section>
      <footer className="app-footer"><span>数据保存在本机 · 采样精度约 ±{dashboard?.settings.interval_seconds || 10} 秒</span><span>上次刷新 {formatTime(dashboard?.generated_at, true)}</span></footer>
    </div>

    {notice && <div className="notice" role="status"><Check />{notice}</div>}
    {nodeDialogOpen && <NodeDialog open node={editingNode} saving={saving} onOpenChange={(open) => { setNodeDialogOpen(open); if (!open) setEditingNode(null) }} onSave={saveNode} />}
    {settingsOpen && dashboard && <SettingsDialog open settings={dashboard.settings} saving={saving} onOpenChange={setSettingsOpen} onSave={saveSettings} />}
    <AlertDialog open={Boolean(deleteNode)} onOpenChange={(open) => !open && setDeleteNode(null)}><AlertDialogContent className="border-white/10 bg-[#0b1724] text-[#ecf8ff]"><AlertDialogHeader><AlertDialogTitle>删除 {deleteNode?.name}？</AlertDialogTitle><AlertDialogDescription className="text-slate-400">节点配置、全部延迟采样和 Timeout 历史都会被永久删除。</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>取消</AlertDialogCancel><AlertDialogAction variant="destructive" onClick={() => void confirmDelete()}>确认删除</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </main>
}
