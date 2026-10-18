import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Alert } from '../components/ui';
import { ClassBadge, Empty } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { formatBytes, formatDate, ownerName } from '../lib/format';
import { filesApi } from '../services/filesApi';

export default function Files() {
  const [scope, setScope] = useState<'owned' | 'shared'>('owned');
  const [q, setQ] = useState('');
  const { data, error, isLoading } = useQuery({ queryKey: ['files', scope, q], queryFn: () => filesApi.list(scope, q) });

  const tab = (s: typeof scope, label: string) => (
    <button onClick={() => setScope(s)} className={`rounded-md px-3 py-1.5 text-sm ${scope === s ? 'bg-panel text-signal' : 'text-mute hover:text-fog'}`}>{label}</button>
  );
  return (
    <div className="max-w-5xl">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Files</h1>
        <Link to="/files/upload" className="rounded-md bg-signal px-4 py-2.5 text-sm font-semibold text-ink hover:bg-signal/90">Upload file</Link>
      </div>
      <div className="mt-6 flex flex-wrap items-center gap-2">
        {tab('owned', 'My files')}
        {tab('shared', 'Shared with me')}
        <input aria-label="Search files" placeholder="Search by name" value={q} onChange={(e) => setQ(e.target.value)}
          className="ml-auto w-56 rounded-md border border-line bg-ink px-3 py-2 text-sm placeholder:text-mute/60" />
      </div>
      {error && <div className="mt-4"><Alert kind="error">{getErrorMessage(error)}</Alert></div>}
      <div className="mt-4 overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-sm">
          <thead className="bg-panel text-mute">
            <tr>{['Name', 'Classification', 'Size', 'Version', scope === 'owned' ? 'Updated' : 'Owner'].map((h) => <th key={h} className="px-4 py-3 font-medium">{h}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-line">
            {data?.files.map((f) => (
              <tr key={f.id} className="hover:bg-panel/60">
                <td className="px-4 py-3"><Link to={`/files/${f.id}`} className="font-medium text-signal hover:underline">{f.fileName}</Link></td>
                <td className="px-4 py-3"><ClassBadge value={f.classification} /></td>
                <td className="px-4 py-3 text-mute">{formatBytes(f.size)}</td>
                <td className="px-4 py-3 text-mute">v{f.currentVersion}</td>
                <td className="px-4 py-3 text-mute">{scope === 'owned' ? formatDate(f.updatedAt) : ownerName(f.owner)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!isLoading && data?.files.length === 0 && (
          <Empty>{scope === 'owned' ? 'No files yet. Upload one to get started.' : 'Nothing has been shared with you.'}</Empty>
        )}
      </div>
    </div>
  );
}
