import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Alert, Button } from '../components/ui';
import { ClassBadge, Empty, Panel, PlainInput, Select } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { formatDate } from '../lib/format';
import { filesApi, roomsApi } from '../services/filesApi';
import { useAuthStore } from '../store/authStore';
import type { RoomRole } from '../types/api';

export default function DataRoomDetail() {
  const { id = '' } = useParams();
  const me = useAuthStore((s) => s.user)!;
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data, error } = useQuery({ queryKey: ['room', id], queryFn: () => roomsApi.get(id), retry: false });
  const refresh = () => { qc.invalidateQueries({ queryKey: ['room', id] }); qc.invalidateQueries({ queryKey: ['rooms'] }); };
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<RoomRole>('viewer');
  const [attach, setAttach] = useState('');
  const mine = useQuery({ queryKey: ['files', 'owned', ''], queryFn: () => filesApi.list('owned') });

  const act = useMutation({ mutationFn: (fn: () => Promise<unknown>) => fn(), onSuccess: refresh });
  const audit = useQuery({ queryKey: ['room-audit', id], queryFn: () => roomsApi.audit(id), enabled: data?.room.myRole === 'manager' });
  const del = useMutation({ mutationFn: () => roomsApi.remove(id), onSuccess: () => { qc.invalidateQueries({ queryKey: ['rooms'] }); navigate('/rooms'); } });

  if (error) return <Alert kind="error">{getErrorMessage(error)}</Alert>;
  if (!data) return <p className="text-sm text-mute">Loading…</p>;
  const room = data.room;
  const manager = room.myRole === 'manager';
  const canUpload = room.myRole !== 'viewer';
  const isOwner = room.owner?.id === me.id;
  const candidates = mine.data?.files.filter((f) => !f.dataRoom && f.classification !== 'restricted') ?? [];

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{room.name}</h1>
        <p className="mt-1 text-sm text-mute">{room.description} · you are {room.myRole} · accepts up to {room.permissions.maxClassification} · viewers {room.permissions.viewerCanDownload ? 'can' : 'cannot'} download</p>
      </div>
      {act.error && <Alert kind="error">{getErrorMessage(act.error)}</Alert>}

      <Panel title="Files">
        <ul className="divide-y divide-line text-sm">
          {room.files?.map((f) => (
            <li key={f.id} className="flex items-center justify-between py-2.5">
              <span><Link to={`/files/${f.id}`} className="text-signal hover:underline">{f.fileName}</Link> <ClassBadge value={f.classification} /></span>
              {(manager || (typeof f.owner === 'object' && f.owner.id === me.id)) && (
                <button className="text-danger hover:underline" onClick={() => act.mutate(() => roomsApi.detachFile(id, f.id))}>Remove from room</button>
              )}
            </li>
          ))}
        </ul>
        {room.files?.length === 0 && <Empty>No files in this room.</Empty>}
        {canUpload && candidates.length > 0 && (
          <div className="mt-4 flex items-end gap-3">
            <div className="flex-1"><Select label="Add one of your files" value={attach} onChange={(e) => setAttach(e.target.value)}>
              <option value="">Choose a file</option>{candidates.map((f) => <option key={f.id} value={f.id}>{f.fileName}</option>)}
            </Select></div>
            <Button disabled={!attach} onClick={() => act.mutate(async () => { await roomsApi.attachFile(id, attach); setAttach(''); })}>Add</Button>
          </div>
        )}
      </Panel>

      <Panel title={`Members (${room.memberCount})`}>
        <ul className="divide-y divide-line text-sm">
          <li className="flex justify-between py-2.5"><span>{room.owner?.name} <span className="text-mute">{room.owner?.email}</span></span><span className="text-mute">owner</span></li>
          {room.members?.map((m) => (
            <li key={m.user.id} className="flex items-center justify-between py-2.5">
              <span>{m.user.name} <span className="text-mute">{m.user.email}</span></span>
              <span className="flex items-center gap-3">
                {manager ? (
                  <select aria-label={`Role for ${m.user.name}`} value={m.role} onChange={(e) => act.mutate(() => roomsApi.setRole(id, m.user.id, e.target.value as RoomRole))}
                    className="rounded-md border border-line bg-ink px-2 py-1 text-sm">
                    <option value="viewer">viewer</option><option value="editor">editor</option>{room.myRole === 'manager' && <option value="manager">manager</option>}
                  </select>
                ) : <span className="text-mute">{m.role}</span>}
                {(manager || m.user.id === me.id) && <button className="text-danger hover:underline" onClick={() => act.mutate(() => roomsApi.removeMember(id, m.user.id))}>{m.user.id === me.id ? 'Leave' : 'Remove'}</button>}
              </span>
            </li>
          ))}
        </ul>
        {manager && (
          <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_150px_auto] sm:items-end">
            <PlainInput label="Add member by email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            <Select label="Role" value={role} onChange={(e) => setRole(e.target.value as RoomRole)}><option value="viewer">viewer</option><option value="editor">editor</option><option value="manager">manager</option></Select>
            <Button disabled={!email} onClick={() => act.mutate(async () => { await roomsApi.addMember(id, { email, role }); setEmail(''); })}>Add</Button>
          </div>
        )}
      </Panel>

      {manager && (
        <Panel title="Room policy">
          <div className="flex flex-wrap items-end gap-4">
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={room.permissions.viewerCanDownload}
              onChange={(e) => act.mutate(() => roomsApi.update(id, { permissions: { viewerCanDownload: e.target.checked } }))} /> Viewers can download</label>
            <Select label="Highest classification allowed" value={room.permissions.maxClassification}
              onChange={(e) => act.mutate(() => roomsApi.update(id, { permissions: { maxClassification: e.target.value } }))}>
              <option value="public">public</option><option value="internal">internal</option><option value="confidential">confidential</option>
            </Select>
            {isOwner && <Button variant="ghost" loading={del.isPending} onClick={() => { if (confirm('Delete this room? Files are kept but leave the room.')) del.mutate(); }}>Delete room</Button>}
          </div>
        </Panel>
      )}

      {manager && (
        <Panel title="Room audit log">
          <table className="w-full text-left text-sm">
            <thead className="text-mute"><tr><th className="pb-2 font-medium">When</th><th className="pb-2 font-medium">Who</th><th className="pb-2 font-medium">Action</th></tr></thead>
            <tbody className="divide-y divide-line">
              {audit.data?.items.map((i) => <tr key={i.id}><td className="py-2 pr-4 text-mute">{formatDate(i.timestamp)}</td><td className="py-2 pr-4">{i.actor?.email ?? 'system'}</td><td className="py-2">{i.action}</td></tr>)}
            </tbody>
          </table>
          {audit.data?.items.length === 0 && <Empty>No activity yet.</Empty>}
        </Panel>
      )}
    </div>
  );
}
