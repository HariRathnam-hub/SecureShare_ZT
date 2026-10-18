import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Alert, Button } from '../components/ui';
import { ClassBadge, DownloadPanel, PlainInput } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { formatBytes, formatDate, ownerName } from '../lib/format';
import { linksApi } from '../services/filesApi';

export default function SharedLinkOpen() {
  const { token = '' } = useParams();
  const [password, setPassword] = useState('');
  const open = useMutation({ mutationFn: () => linksApi.open(token, password || undefined) });
  const d = open.data;

  return (
    <div className="max-w-lg space-y-5">
      <h1 className="text-2xl font-semibold">Shared file</h1>
      {!d && (
        <>
          <p className="text-sm text-mute">Opening this link is recorded against your account.</p>
          {open.error && <Alert kind="error">{getErrorMessage(open.error)}</Alert>}
          <PlainInput label="Link password (if one was set)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
          <Button onClick={() => open.mutate()} loading={open.isPending}>Open link</Button>
        </>
      )}
      {d && (
        <div className="space-y-4 rounded-lg border border-line bg-panel p-4">
          <div className="flex items-center gap-3"><p className="font-medium">{d.file.fileName}</p><ClassBadge value={d.file.classification} /></div>
          <p className="text-sm text-mute">
            {formatBytes(d.file.size)} · from {ownerName(d.file.owner)} · link expires {formatDate(d.expiresAt)}
            {d.remainingDownloads !== null && ` · ${d.remainingDownloads} download${d.remainingDownloads === 1 ? '' : 's'} left`}
          </p>
          <DownloadPanel endpoint="/links/download" body={{ token, password: password || undefined }} filename={d.file.fileName} requiresPurpose={d.requiresPurpose} fileId={d.file.id} label="Download file" />
        </div>
      )}
    </div>
  );
}
