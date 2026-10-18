import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import { z } from 'zod';
import { Alert, Button } from '../components/ui';
import { PlainInput, Select } from '../components/fileUi';
import { getErrorMessage } from '../lib/api';
import { filesApi, roomsApi } from '../services/filesApi';

const schema = z.object({
  file: z.instanceof(FileList).refine((l) => l.length === 1, 'Choose a file').refine((l) => !l[0] || l[0].size <= 25 * 1024 * 1024, 'Max 25 MB'),
  classification: z.enum(['public', 'internal', 'confidential', 'restricted']),
  roomId: z.string().optional(),
  availableFrom: z.string().optional(),
  availableUntil: z.string().optional(),
}).refine((v) => !v.availableFrom || !v.availableUntil || new Date(v.availableUntil) > new Date(v.availableFrom), {
  path: ['availableUntil'],
  message: 'Must be after the start time',
});
type Form = z.infer<typeof schema>;

const HELP: Record<string, string> = {
  public: 'Any signed-in user can download.',
  internal: 'Only people you share with, or members of its data room.',
  confidential: 'Like internal, but every download needs a stated purpose and is audited.',
  restricted: 'Owner plus people you approve through an access request (max 7 days). Purpose required on every download. No direct shares, links or rooms.',
};

export default function UploadFile() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const rooms = useQuery({ queryKey: ['rooms'], queryFn: roomsApi.list });
  const { register, handleSubmit, watch, formState: { errors } } = useForm<Form>({ resolver: zodResolver(schema), defaultValues: { classification: 'internal' } });
  const m = useMutation({
    mutationFn: (v: Form) => {
      const fd = new FormData();
      fd.append('classification', v.classification);
      if (v.roomId) fd.append('roomId', v.roomId);
      if (v.availableFrom) fd.append('availableFrom', new Date(v.availableFrom).toISOString());
      if (v.availableUntil) fd.append('availableUntil', new Date(v.availableUntil).toISOString());
      fd.append('file', v.file[0]); // file last so fields are parsed first
      return filesApi.upload(fd);
    },
    onSuccess: ({ file }) => {
      qc.invalidateQueries({ queryKey: ['files'] });
      navigate(`/files/${file.id}`);
    },
  });
  const cls = watch('classification');
  const uploadable = rooms.data?.rooms.filter((r) => r.myRole !== 'viewer') ?? [];

  return (
    <div className="max-w-lg">
      <h1 className="text-2xl font-semibold">Upload file</h1>
      <p className="mt-2 text-sm text-mute">Files are never reachable by a public URL. Every download goes through identity, classification and time-lock checks and is audited.</p>
      <form onSubmit={handleSubmit((v) => m.mutate(v))} className="mt-6 space-y-4" noValidate>
        {m.error && <Alert kind="error">{getErrorMessage(m.error)}</Alert>}
        <div>
          <label htmlFor="file" className="mb-1.5 block text-sm font-medium">File</label>
          <input id="file" type="file" {...register('file')} className="block w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-panel file:px-3 file:py-2 file:text-fog" />
          {errors.file && <p className="mt-1.5 text-sm text-danger">{errors.file.message as string}</p>}
        </div>
        <Select label="Classification" {...register('classification')}>
          <option value="public">public</option><option value="internal">internal</option>
          <option value="confidential">confidential</option><option value="restricted">restricted</option>
        </Select>
        <p className="-mt-2 text-sm text-mute">{HELP[cls]}</p>
        {cls !== 'restricted' && uploadable.length > 0 && (
          <Select label="Data room (optional)" {...register('roomId')}>
            <option value="">None</option>
            {uploadable.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </Select>
        )}
        <fieldset className="space-y-3 rounded-md border border-line p-3">
          <legend className="px-1 text-sm font-medium">Time lock (optional)</legend>
          <div className="grid gap-3 sm:grid-cols-2">
            <PlainInput label="Available from" type="datetime-local" {...register('availableFrom')} />
            <div>
              <PlainInput label="Available until" type="datetime-local" {...register('availableUntil')} />
              {errors.availableUntil && <p className="mt-1.5 text-sm text-danger">{errors.availableUntil.message}</p>}
            </div>
          </div>
          <p className="text-xs text-mute">Outside this window everyone except you is denied.</p>
        </fieldset>
        <Button type="submit" loading={m.isPending}>Upload file</Button>
      </form>
    </div>
  );
}
