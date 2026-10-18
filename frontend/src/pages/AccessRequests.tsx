import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Alert } from '../components/ui';
import { ClassBadge, Empty } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { formatDate } from '../lib/format';
import { requestsApi } from '../services/filesApi';

const tone = { pending: 'text-amber-300', approved: 'text-signal', rejected: 'text-danger' } as const;

export default function AccessRequests() {
  const qc = useQueryClient();
  const [box, setBox] = useState<'incoming' | 'outgoing'>('incoming');
  const [days, setDays] = useState(7);
  const { data, error, isLoading } = useQuery({ queryKey: ['requests', box], queryFn: () => requestsApi.list(box) });
  const done = () => qc.invalidateQueries({ queryKey: ['requests'] });
  const approve = useMutation({ mutationFn: (id: string) => requestsApi.approve(id, { expiresInDays: days, permission: 'download' }), onSuccess: done });
  const reject = useMutation({ mutationFn: requestsApi.reject, onSuccess: done });
  const tab = (b: typeof box, label: string) => (
    <button onClick={() => setBox(b)} className={`rounded-md px-3 py-1.5 text-sm ${box === b ? 'bg-panel text-signal' : 'text-mute hover:text-fog'}`}>{label}</button>
  );
  return (
    <div className="max-w-5xl">
      <h1 className="text-2xl font-semibold">Access requests</h1>
      <div className="mt-6 flex items-center gap-2">
        {tab('incoming', 'For my files')}{tab('outgoing', 'My requests')}
        {box === 'incoming' && (
          <label className="ml-auto flex items-center gap-2 text-sm text-mute">Grant lasts
            <input type="number" min={1} max={30} value={days} onChange={(e) => setDays(Math.min(30, Math.max(1, Number(e.target.value) || 1)))} className="w-16 rounded-md border border-line bg-ink px-2 py-1.5 text-fog" /> days
          </label>
        )}
      </div>
      {(error || approve.error || reject.error) && <div className="mt-4"><Alert kind="error">{getErrorMessage(error ?? approve.error ?? reject.error)}</Alert></div>}
      <div className="mt-4 space-y-3">
        {data?.requests.map((r) => (
          <article key={r.id} className="rounded-lg border border-line bg-panel p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm">
                <Link to={`/files/${r.file.id}`} className="font-medium text-signal hover:underline">{r.file.fileName ?? 'File'}</Link>{' '}
                {r.file.classification && <ClassBadge value={r.file.classification} />}
              </p>
              <span className={`text-sm ${tone[r.status]}`}>{r.status}{r.status === 'approved' && r.expiresAt ? ` until ${formatDate(r.expiresAt)}` : ''}</span>
            </div>
            <p className="mt-2 text-sm text-mute">
              {box === 'incoming' && 'name' in r.requester ? `${r.requester.name} (${r.requester.email}) · ` : ''}purpose: {r.purpose} · {formatDate(r.createdAt)}
            </p>
            <p className="mt-2 text-sm">{r.reason}</p>
            {box === 'incoming' && r.status === 'pending' && r.file.classification === 'restricted' && (
              <p className="mt-2 text-xs text-amber-300">Restricted file: approval can last at most 7 days.</p>
            )}
            {box === 'incoming' && r.status === 'pending' && (
              <div className="mt-3 flex gap-4 text-sm">
                <button className="text-signal hover:underline" onClick={() => approve.mutate(r.id)}>Approve</button>
                <button className="text-danger hover:underline" onClick={() => reject.mutate(r.id)}>Reject</button>
              </div>
            )}
          </article>
        ))}
        {!isLoading && data?.requests.length === 0 && <Empty>No requests here.</Empty>}
      </div>
    </div>
  );
}
