import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { z } from 'zod';
import { Alert, Button, Field } from '../components/ui';
import { Empty, Panel } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { roomsApi } from '../services/filesApi';

const schema = z.object({ name: z.string().trim().min(2, 'Name is too short').max(100), description: z.string().trim().max(500).optional() });
type Form = z.infer<typeof schema>;

export default function DataRooms() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['rooms'], queryFn: roomsApi.list });
  const { register, handleSubmit, reset, formState: { errors } } = useForm<Form>({ resolver: zodResolver(schema) });
  const create = useMutation({ mutationFn: roomsApi.create, onSuccess: () => { reset(); qc.invalidateQueries({ queryKey: ['rooms'] }); } });
  return (
    <div className="max-w-4xl space-y-6">
      <h1 className="text-2xl font-semibold">Data rooms</h1>
      <Panel title="New data room">
        <form onSubmit={handleSubmit((v) => create.mutate(v))} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end" noValidate>
          <Field label="Name" error={errors.name?.message} {...register('name')} />
          <Field label="Description (optional)" {...register('description')} />
          <Button type="submit" loading={create.isPending}>Create room</Button>
        </form>
        {create.error && <div className="mt-3"><Alert kind="error">{getErrorMessage(create.error)}</Alert></div>}
      </Panel>
      <div className="grid gap-3 sm:grid-cols-2">
        {data?.rooms.map((r) => (
          <Link key={r.id} to={`/rooms/${r.id}`} className="rounded-lg border border-line bg-panel p-4 hover:border-signal/60">
            <p className="font-medium">{r.name}</p>
            <p className="mt-1 line-clamp-2 text-sm text-mute">{r.description || 'No description'}</p>
            <p className="mt-3 text-xs text-mute">{r.fileCount} files · {r.memberCount} members · you are {r.myRole}</p>
          </Link>
        ))}
      </div>
      {!isLoading && data?.rooms.length === 0 && <Empty>No data rooms yet. Create one for a group that needs shared, controlled access.</Empty>}
    </div>
  );
}
