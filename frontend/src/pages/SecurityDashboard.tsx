import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, Panel } from '../components/fileUi';
import { Alert } from '../components/ui';
import { getErrorMessage } from '../lib/api';
import { formatDate } from '../lib/format';
import { securityApi } from '../services/securityApi';
import type { PolicyDecision, SecurityRow } from '../types/api';

const pill = (tone: 'ok' | 'warn' | 'bad' | 'off') =>
  ({ ok: 'border-signal/50 text-signal', warn: 'border-amber-400/50 text-amber-300', bad: 'border-danger/60 text-danger', off: 'border-line text-mute' })[tone];
const Pill = ({ tone, children }: { tone: Parameters<typeof pill>[0]; children: string }) => (
  <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${pill(tone)}`}>{children}</span>
);
const decisionTone: Record<PolicyDecision, Parameters<typeof pill>[0]> = { ALLOW: 'ok', REQUIRE_APPROVAL: 'warn', DENY: 'bad' };
const decisionOf = (r: SecurityRow) => r.detail.split(':')[0] as PolicyDecision;

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <p className="text-xs text-mute">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${tone ?? ''}`}>{value}</p>
    </div>
  );
}

function Table({ rows, cols }: { rows: SecurityRow[]; cols: { head: string; cell: (r: SecurityRow) => React.ReactNode }[] }) {
  if (!rows.length) return <Empty>Nothing recorded yet.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-mute"><tr>{cols.map((c) => <th key={c.head} className="pb-2 pr-4 font-medium">{c.head}</th>)}</tr></thead>
        <tbody className="divide-y divide-line">
          {rows.map((r) => <tr key={r.id}>{cols.map((c) => <td key={c.head} className="py-2 pr-4 align-top">{c.cell(r)}</td>)}</tr>)}
        </tbody>
      </table>
    </div>
  );
}

const when = { head: 'When', cell: (r: SecurityRow) => <span className="whitespace-nowrap text-mute">{formatDate(r.timestamp)}</span> };
const who = { head: 'Who', cell: (r: SecurityRow) => r.actor?.email ?? <span className="text-mute">unknown</span> };
const fileCol = { head: 'File', cell: (r: SecurityRow) => r.file?.name ?? <span className="text-mute">—</span> };
const ipCol = { head: 'IP', cell: (r: SecurityRow) => <span className="text-mute">{r.ip ?? ''}</span> };

export default function SecurityDashboard() {
  const [hours, setHours] = useState(24);
  const { data, error, isLoading, dataUpdatedAt } = useQuery({
    queryKey: ['security-overview', hours], queryFn: () => securityApi.overview(hours), refetchInterval: 30_000,
  });

  if (isLoading) return <p className="text-sm text-mute">Loading…</p>;
  if (error || !data) return <Alert kind="error">{getErrorMessage(error)}</Alert>;
  const { cloudflare: cf, tunnel, stats, recent } = data;

  return (
    <div className="max-w-6xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Security</h1>
          <p className="mt-1 text-sm text-mute">Built from the audit log. Updated {new Date(dataUpdatedAt).toLocaleTimeString()}.</p>
        </div>
        <label className="text-sm text-mute">
          Window{' '}
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))} className="rounded-md border border-line bg-ink px-2 py-1.5 text-fog">
            <option value={24}>last 24 hours</option><option value={168}>last 7 days</option><option value={720}>last 30 days</option>
          </select>
        </label>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="Cloudflare Access">
          <div className="flex flex-wrap gap-2">
            <Pill tone={cf.accessEnabled ? 'ok' : 'off'}>{cf.accessEnabled ? 'enabled' : 'disabled'}</Pill>
            <Pill tone={cf.accessConfigured ? 'ok' : 'warn'}>{cf.accessConfigured ? 'configured' : 'unconfigured'}</Pill>
          </div>
          <dl className="mt-3 space-y-1.5 text-sm">
            {cf.teamDomain && <div className="flex justify-between"><dt className="text-mute">Team domain</dt><dd>{cf.teamDomain}</dd></div>}
            {cf.accessEnabled && (
              <>
                <div className="flex justify-between"><dt className="text-mute">Assertions verified (since server start)</dt><dd>{cf.verifiedSinceStart}</dd></div>
                <div className="flex justify-between"><dt className="text-mute">Rejected (since server start)</dt><dd>{cf.rejectedSinceStart}</dd></div>
                {cf.lastRejectedAt && <div className="flex justify-between"><dt className="text-mute">Last rejection</dt><dd>{cf.lastRejectReason} · {formatDate(cf.lastRejectedAt)}</dd></div>}
              </>
            )}
          </dl>
          <p className="mt-3 text-xs text-mute">
            {cf.accessEnabled
              ? 'Every API request must carry a Cloudflare Access assertion that verifies. “Verified” counts only requests that actually passed verification.'
              : 'Access verification is off. Sign-in uses the app’s own authentication only. Enabling it needs a Cloudflare-managed hostname; see the README.'}
          </p>
        </Panel>

        <Panel title="Tunnel">
          <Pill tone={tunnel.status === 'manually_configured' ? 'warn' : 'off'}>{tunnel.status === 'manually_configured' ? 'manually configured' : 'not configured'}</Pill>
          <dl className="mt-3 space-y-1.5 text-sm">
            {tunnel.publicUrl && <div className="flex justify-between gap-4"><dt className="text-mute">Declared URL</dt><dd className="truncate">{tunnel.publicUrl}</dd></div>}
            <div className="flex justify-between gap-4"><dt className="text-mute">Allowed origins</dt><dd className="text-right">{tunnel.allowedOrigins.join(', ')}</dd></div>
          </dl>
          <p className="mt-3 text-xs text-mute">
            This reflects the TUNNEL_PUBLIC_URL setting only. The server does not detect whether cloudflared is running. Quick Tunnel URLs are temporary and for demos.
          </p>
        </Panel>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
        <Stat label="Allowed" value={stats.decisions.ALLOW} tone="text-signal" />
        <Stat label="Approval required" value={stats.decisions.REQUIRE_APPROVAL} tone="text-amber-300" />
        <Stat label="Denied by policy" value={stats.decisions.DENY} tone="text-danger" />
        <Stat label="Failed logins" value={stats.failedLogins} />
        <Stat label="Downloads" value={stats.downloads} />
        <Stat label="Access requests" value={stats.accessRequests} />
        <Stat label="Access denied" value={stats.accessDenied} />
      </div>

      <Panel title="Recent security events">
        <Table rows={recent.securityEvents} cols={[when, { head: 'Event', cell: (r) => r.action }, who, { head: 'Detail', cell: (r) => <span className="break-words text-mute">{r.detail}</span> }, ipCol]} />
      </Panel>

      <Panel title="Policy decisions">
        <Table rows={recent.policyDecisions} cols={[when, { head: 'Decision', cell: (r) => <Pill tone={decisionTone[decisionOf(r)] ?? 'off'}>{decisionOf(r)}</Pill> }, who, fileCol,
          { head: 'Reason', cell: (r) => <span className="break-words text-mute">{r.detail.split(': ').slice(1).join(': ')}</span> }]} />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Failed login attempts">
          <Table rows={recent.failedLogins} cols={[when, { head: 'Account', cell: (r) => r.actor?.email ?? <span className="text-mute">unknown account</span> }, { head: 'Reason', cell: (r) => <span className="text-mute">{r.detail}</span> }, ipCol]} />
        </Panel>
        <Panel title="Access requests">
          <Table rows={recent.accessRequests} cols={[when, { head: 'Event', cell: (r) => r.action.replace('_', ' ').toLowerCase() }, who, fileCol]} />
        </Panel>
      </div>

      <Panel title="Recent downloads">
        <Table rows={recent.downloads} cols={[when, who, fileCol, { head: 'Class', cell: (r) => r.file?.classification ?? '' }, ipCol]} />
      </Panel>
    </div>
  );
}
