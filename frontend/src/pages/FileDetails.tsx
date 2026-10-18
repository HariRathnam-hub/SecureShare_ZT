import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Alert, Button } from '../components/ui';
import { ClassBadge, DownloadPanel, Empty, Panel, PlainInput, Select, TextArea } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { formatBytes, formatDate, ownerName, toLocalInput } from '../lib/format';
import { downloadVia, filesApi, linksApi } from '../services/filesApi';
import { Classification, FileDTO, PURPOSES } from '../types/api';

export default function FileDetails() {
  const { id = '' } = useParams();
  const { data, error, isLoading } = useQuery({ queryKey: ['file', id], queryFn: () => filesApi.get(id), retry: false });

  if (isLoading) return <p className="text-sm text-mute">Loading…</p>;
  if (error) {
    const status = (error as any)?.response?.status;
    return status === 404 ? <RequestAccess fileId={id} /> : <Alert kind="error">{getErrorMessage(error)}</Alert>;
  }
  const { file, versions } = data!;
  const a = file.access!;

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold">{file.fileName}</h1>
          <ClassBadge value={file.classification} />
        </div>
        <p className="mt-2 text-sm text-mute">
          {formatBytes(file.size)} · v{file.currentVersion} · owned by {a.isOwner ? 'you' : ownerName(file.owner)} · updated {formatDate(file.updatedAt)}
        </p>
        {(file.availableFrom || file.availableUntil) && (
          <p className="mt-1 text-sm text-amber-300">
            Time-locked:{file.availableFrom && ` available from ${formatDate(file.availableFrom)}`}{file.availableUntil && ` until ${formatDate(file.availableUntil)}`}
          </p>
        )}
      </div>

      <Panel title="Download">
        <DownloadPanel
          endpoint={`/files/${file.id}/download`} filename={file.fileName} requiresPurpose={a.requiresPurpose} fileId={file.id}
          disabledReason={a.canDownload ? null : a.reason ?? 'Download not permitted'}
        />
        {!a.isOwner && <p className="mt-3 text-xs text-mute">PDFs are watermarked with your identity, time, IP and a download ID. Every download is audited.</p>}
      </Panel>

      <Versions file={file} versions={versions} />
      {a.isOwner && <OwnerTools file={file} />}
    </div>
  );
}

function Versions({ file, versions }: { file: FileDTO; versions: { versionNumber: number; size: number; createdAt: string; uploadedBy: { name: string } }[] }) {
  const qc = useQueryClient();
  const owner = file.access!.isOwner;
  const up = useMutation({
    mutationFn: (f: File) => { const fd = new FormData(); fd.append('file', f); return filesApi.addVersion(file.id, fd); },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['file', file.id] }),
  });
  return (
    <Panel title="Versions" aside={owner && (
      <label className="cursor-pointer text-sm text-signal hover:underline">
        Upload new version
        <input type="file" className="sr-only" onChange={(e) => e.target.files?.[0] && up.mutate(e.target.files[0])} />
      </label>
    )}>
      {up.error && <div className="mb-3"><Alert kind="error">{getErrorMessage(up.error)}</Alert></div>}
      <ul className="divide-y divide-line text-sm">
        {versions.map((v) => (
          <li key={v.versionNumber} className="flex items-center justify-between py-2.5">
            <span>v{v.versionNumber}{v.versionNumber === file.currentVersion && <span className="ml-2 text-signal">current</span>}
              <span className="ml-3 text-mute">{formatBytes(v.size)} · {v.uploadedBy.name} · {formatDate(v.createdAt)}</span></span>
            {owner && v.versionNumber !== file.currentVersion && (
              <button className="text-signal hover:underline" onClick={() => downloadVia(`/files/${file.id}/download`, { version: v.versionNumber }, file.fileName)}>Download</button>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function OwnerTools({ file }: { file: FileDTO }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const refresh = () => { qc.invalidateQueries({ queryKey: ['file', file.id] }); qc.invalidateQueries({ queryKey: ['files'] }); };
  const [cls, setCls] = useState<Classification>(file.classification);
  const [start, setStart] = useState(toLocalInput(file.availableFrom));
  const [end, setEnd] = useState(toLocalInput(file.availableUntil));
  const [name, setName] = useState(file.fileName);
  const save = useMutation({
    mutationFn: () => filesApi.update(file.id, {
      fileName: name, classification: cls,
      availableFrom: start ? new Date(start).toISOString() : null,
      availableUntil: end ? new Date(end).toISOString() : null,
    }),
    onSuccess: refresh,
  });
  const del = useMutation({ mutationFn: () => filesApi.remove(file.id), onSuccess: () => { qc.invalidateQueries({ queryKey: ['files'] }); navigate('/files'); } });

  return (
    <>
      <Panel title="Settings">
        <div className="space-y-4">
          {save.error && <Alert kind="error">{getErrorMessage(save.error)}</Alert>}
          {save.isSuccess && <Alert kind="success">Saved.</Alert>}
          <PlainInput label="Display name" value={name} onChange={(e) => setName(e.target.value)} />
          <Select label="Classification" value={cls} onChange={(e) => setCls(e.target.value as Classification)}>
            <option value="public">public</option><option value="internal">internal</option>
            <option value="confidential">confidential</option><option value="restricted">restricted</option>
          </Select>
          {CLASS_WARN(file.classification, cls)}
          <div className="grid gap-3 sm:grid-cols-2">
            <PlainInput label="Available from" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
            <PlainInput label="Available until" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
          </div>
          <p className="text-xs text-mute">Time lock: outside this window nobody but you can download. Either side may be left empty; clear both to remove the lock.</p>
          <div className="flex gap-3">
            <Button onClick={() => save.mutate()} loading={save.isPending}>Save settings</Button>
            <Button variant="ghost" onClick={() => { if (confirm('Permanently delete this file and all versions?')) del.mutate(); }} loading={del.isPending}>Delete file</Button>
          </div>
        </div>
      </Panel>
      {file.classification !== 'restricted' ? (
        <><ShareUser file={file} onChange={refresh} /><CreateLink file={file} /></>
      ) : (
        <Panel title="Sharing">
          <p className="text-sm text-mute">
            Restricted files can't be shared directly or by link. People ask for access from this file's page; you approve each request for up to 7 days,
            and every download needs a purpose and reason. Review requests under Access requests.
          </p>
        </Panel>
      )}
      <AuditTrail fileId={file.id} />
    </>
  );
}

const CLASS_WARN = (from: Classification, to: Classification) =>
  to === 'restricted' && from !== 'restricted' ? <Alert kind="error">Restricted removes direct shares and deactivates every link. Only approved access requests (max 7 days) can grant access afterwards.</Alert>
  : to === 'confidential' && from !== 'confidential' ? <Alert kind="error">Raising classification deactivates existing share links.</Alert> : null;

function ShareUser({ file, onChange }: { file: FileDTO; onChange: () => void }) {
  const [email, setEmail] = useState('');
  const [permission, setPermission] = useState<'view' | 'download'>('download');
  const [expires, setExpires] = useState('');
  const share = useMutation({
    mutationFn: () => filesApi.share(file.id, { email, permission, expiresAt: expires ? new Date(expires).toISOString() : undefined }),
    onSuccess: () => { setEmail(''); onChange(); },
  });
  const revoke = useMutation({ mutationFn: (uid: string) => filesApi.revokeShare(file.id, uid), onSuccess: onChange });
  return (
    <Panel title="Share with people">
      {(share.error || revoke.error) && <div className="mb-3"><Alert kind="error">{getErrorMessage(share.error ?? revoke.error)}</Alert></div>}
      <div className="grid gap-3 sm:grid-cols-[1fr_140px_190px_auto] sm:items-end">
        <PlainInput label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <Select label="Permission" value={permission} onChange={(e) => setPermission(e.target.value as any)}><option value="download">download</option><option value="view">view only</option></Select>
        <PlainInput label="Expires (optional)" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
        <Button onClick={() => share.mutate()} loading={share.isPending} disabled={!email}>Share</Button>
      </div>
      <ul className="mt-4 divide-y divide-line text-sm">
        {file.sharedWith?.map((g) => {
          const u = typeof g.user === 'object' ? g.user : null;
          return (
            <li key={u?.id ?? String(g.user)} className="flex items-center justify-between py-2.5">
              <span>{u?.email ?? String(g.user)} <span className="text-mute">· {g.permission}{g.expiresAt ? ` · until ${formatDate(g.expiresAt)}` : ''}</span></span>
              {u && <button className="text-danger hover:underline" onClick={() => revoke.mutate(u.id)}>Revoke</button>}
            </li>
          );
        })}
        {!file.sharedWith?.length && <li className="py-2.5 text-mute">Not shared with anyone.</li>}
      </ul>
    </Panel>
  );
}

function CreateLink({ file }: { file: FileDTO }) {
  const qc = useQueryClient();
  const [minutes, setMinutes] = useState('60');
  const [oneTime, setOneTime] = useState(false);
  const [max, setMax] = useState('');
  const [password, setPassword] = useState('');
  const create = useMutation({
    mutationFn: () => linksApi.create(file.id, {
      expiresInMinutes: Number(minutes), maxDownloads: oneTime ? 1 : max ? Number(max) : undefined, password: password || undefined,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['links'] }),
  });
  const url = create.data ? `${window.location.origin}/s/${create.data.token}` : '';
  return (
    <Panel title="Secure share link">
      <div className="space-y-4">
        {create.error && <Alert kind="error">{getErrorMessage(create.error)}</Alert>}
        <div className="grid gap-3 sm:grid-cols-3">
          <PlainInput label="Expires in (minutes)" type="number" min={1} max={43200} value={minutes} onChange={(e) => setMinutes(e.target.value)} />
          <PlainInput label="Max downloads" type="number" min={1} disabled={oneTime} value={oneTime ? '1' : max} onChange={(e) => setMax(e.target.value)} placeholder="Unlimited" />
          <PlainInput label={file.classification === 'confidential' ? 'Password (required)' : 'Password (optional)'} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={oneTime} onChange={(e) => setOneTime(e.target.checked)} /> One-time link (works once)</label>
        <p className="text-xs text-mute">Recipients must sign in to open a link, so every redemption is attributable.</p>
        <Button onClick={() => create.mutate()} loading={create.isPending}>Create link</Button>
        {url && (
          <div className="space-y-2 rounded-md border border-signal/40 p-3">
            <p className="text-sm text-signal">Copy this link now. It is shown only once.</p>
            <input readOnly value={url} onFocus={(e) => e.currentTarget.select()} className="w-full rounded-md border border-line bg-ink px-3 py-2 text-xs" />
            <Button variant="ghost" onClick={() => navigator.clipboard.writeText(url)}>Copy link</Button>
          </div>
        )}
      </div>
    </Panel>
  );
}

function AuditTrail({ fileId }: { fileId: string }) {
  const { data } = useQuery({ queryKey: ['audit-file', fileId], queryFn: () => filesApi.audit(fileId) });
  return (
    <Panel title="Audit trail">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-mute"><tr><th className="pb-2 font-medium">When</th><th className="pb-2 font-medium">Who</th><th className="pb-2 font-medium">Action</th><th className="pb-2 font-medium">IP</th></tr></thead>
          <tbody className="divide-y divide-line">
            {data?.items.map((i) => (
              <tr key={i.id}><td className="py-2 pr-4 text-mute">{formatDate(i.timestamp)}</td><td className="py-2 pr-4">{i.actor?.email ?? 'system'}</td><td className="py-2 pr-4">{i.action}</td><td className="py-2 text-mute">{i.ip ?? ''}</td></tr>
            ))}
          </tbody>
        </table>
        {data && data.items.length === 0 && <Empty>No activity yet.</Empty>}
      </div>
    </Panel>
  );
}

function RequestAccess({ fileId }: { fileId: string }) {
  const [purpose, setPurpose] = useState<string>('project');
  const [reason, setReason] = useState('');
  const m = useMutation({ mutationFn: () => filesApi.requestAccess(fileId, { purpose, reason }) });
  return (
    <div className="max-w-lg space-y-4">
      <h1 className="text-2xl font-semibold">You don't have access to this file</h1>
      <p className="text-sm text-mute">It may not exist, may be owner-only, or may not be shared with you. If you know it exists, you can ask the owner for access.</p>
      {m.isSuccess ? <Alert kind="success">Request sent. You can follow it under Access requests.</Alert> : (
        <>
          {m.error && <Alert kind="error">{getErrorMessage(m.error)}</Alert>}
          <Select label="Purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)}>{PURPOSES.map((p) => <option key={p}>{p}</option>)}</Select>
          <TextArea label="Reason (10+ characters)" value={reason} onChange={(e) => setReason(e.target.value)} />
          <Button onClick={() => m.mutate()} loading={m.isPending} disabled={reason.trim().length < 10}>Request access</Button>
        </>
      )}
    </div>
  );
}
