import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Alert } from '../components/ui';
import { ClassBadge, Empty } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { formatDate } from '../lib/format';
import { linksApi } from '../services/filesApi';

const tone = { active: 'text-signal', expired: 'text-mute', revoked: 'text-danger', exhausted: 'text-mute' } as const;

export default function SharedLinks() {
  const qc = useQueryClient();
  const { data, error, isLoading } = useQuery({ queryKey: ['links'], queryFn: linksApi.list });
  const revoke = useMutation({ mutationFn: linksApi.revoke, onSuccess: () => qc.invalidateQueries({ queryKey: ['links'] }) });
  return (
    <div className="max-w-5xl">
      <h1 className="text-2xl font-semibold">Shared links</h1>
      <p className="mt-2 text-sm text-mute">Links you created. Raw link addresses are never stored, so they can't be shown again. Create a new one from the file's page.</p>
      {(error || revoke.error) && <div className="mt-4"><Alert kind="error">{getErrorMessage(error ?? revoke.error)}</Alert></div>}
      <div className="mt-6 overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-sm">
          <thead className="bg-panel text-mute"><tr>{['File', 'Status', 'Downloads', 'Expires', 'Protection', ''].map((h) => <th key={h} className="px-4 py-3 font-medium">{h}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">
            {data?.links.map((l) => (
              <tr key={l.id}>
                <td className="px-4 py-3">
                  <Link to={`/files/${l.file.id}`} className="text-signal hover:underline">{l.file.fileName ?? 'Deleted file'}</Link>{' '}
                  {l.file.classification && <ClassBadge value={l.file.classification} />}
                </td>
                <td className={`px-4 py-3 ${tone[l.status]}`}>{l.status}</td>
                <td className="px-4 py-3 text-mute">{l.currentDownloads}{l.maxDownloads ? ` / ${l.maxDownloads}` : ''}{l.maxDownloads === 1 ? ' (one-time)' : ''}</td>
                <td className="px-4 py-3 text-mute">{formatDate(l.expiresAt)}</td>
                <td className="px-4 py-3 text-mute">{l.hasPassword ? 'Password' : 'None'}</td>
                <td className="px-4 py-3 text-right">{l.status === 'active' && <button className="text-danger hover:underline" onClick={() => revoke.mutate(l.id)}>Revoke</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!isLoading && data?.links.length === 0 && <Empty>You haven't created any links.</Empty>}
      </div>
    </div>
  );
}
