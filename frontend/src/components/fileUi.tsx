import { ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes, forwardRef, useState } from 'react';
import { getErrorMessage } from '../lib/api';
import { downloadVia, filesApi } from '../services/filesApi';
import { Classification, PURPOSES } from '../types/api';
import { Alert, Button } from './ui';

const badge: Record<Classification, string> = {
  public: 'border-line text-mute',
  internal: 'border-signal/40 text-signal',
  confidential: 'border-amber-400/50 text-amber-300',
  restricted: 'border-danger/60 text-danger',
};
export const ClassBadge = ({ value }: { value: Classification }) => (
  <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${badge[value]}`}>{value}</span>
);

export const Panel = ({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) => (
  <section className="rounded-lg border border-line bg-panel">
    <header className="flex items-center justify-between border-b border-line px-4 py-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      {aside}
    </header>
    <div className="p-4">{children}</div>
  </section>
);

const ctl = 'w-full rounded-md border border-line bg-ink px-3 py-2.5 text-sm text-fog placeholder:text-mute/60 focus:border-signal';
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement> & { label: string }>(
  ({ label, children, ...rest }, ref) => (
    <label className="block text-sm">
      <span className="mb-1.5 block font-medium">{label}</span>
      <select ref={ref} className={ctl} {...rest}>{children}</select>
    </label>
  ),
);
Select.displayName = 'Select';
export const TextArea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; error?: string }>(
  ({ label, error, ...rest }, ref) => (
    <label className="block text-sm">
      <span className="mb-1.5 block font-medium">{label}</span>
      <textarea ref={ref} rows={3} className={ctl} {...rest} />
      {error && <span className="mt-1.5 block text-danger">{error}</span>}
    </label>
  ),
);
TextArea.displayName = 'TextArea';
export const PlainInput = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement> & { label: string }>(
  ({ label, ...rest }, ref) => (
    <label className="block text-sm">
      <span className="mb-1.5 block font-medium">{label}</span>
      <input ref={ref} className={ctl} {...rest} />
    </label>
  ),
);
PlainInput.displayName = 'PlainInput';

export const Empty = ({ children }: { children: ReactNode }) => <p className="py-8 text-center text-sm text-mute">{children}</p>;

/** Download with purpose capture. Used for direct file downloads and share-link redemption. */
export function DownloadPanel(props: {
  endpoint: string; body?: object; filename: string; requiresPurpose: boolean; label?: string; disabledReason?: string | null;
  /** Lets the user ask the owner for approval when the adaptive policy requires it. */
  fileId?: string;
}) {
  const [purpose, setPurpose] = useState<string>('project');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [needs, setNeeds] = useState(props.requiresPurpose);
  const [needsApproval, setNeedsApproval] = useState(false);

  const go = async () => {
    setError('');
    setBusy(true);
    try {
      await downloadVia(props.endpoint, { ...props.body, ...(needs ? { purpose, reason } : {}) }, props.filename);
    } catch (e: any) {
      if (e?.response?.status === 428) setNeeds(true);
      setNeedsApproval(e?.response?.data?.code === 'APPROVAL_REQUIRED');
      setError(getErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const blocked = !!props.disabledReason;
  const incomplete = needs && reason.trim().length < 10;
  return (
    <div className="space-y-3">
      {blocked && <Alert kind="error">{props.disabledReason}</Alert>}
      {needs && !blocked && (
        <div className="space-y-3 rounded-md border border-amber-400/40 p-3">
          <p className="text-sm text-amber-300">This file requires a stated purpose. Your answer is recorded in the audit log.</p>
          <Select label="Purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)}>
            {PURPOSES.map((p) => <option key={p} value={p}>{p}</option>)}
          </Select>
          <TextArea label="Reason (10+ characters)" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
      )}
      {error && <Alert kind="error">{error}</Alert>}
      {needsApproval && props.fileId && <ApprovalRequest fileId={props.fileId} />}
      <Button onClick={go} loading={busy} disabled={blocked || incomplete}>{props.label ?? 'Download'}</Button>
    </div>
  );
}

/** Shown when the adaptive policy asks for owner approval before this download can proceed. */
function ApprovalRequest({ fileId }: { fileId: string }) {
  const [purpose, setPurpose] = useState<string>('project');
  const [reason, setReason] = useState('');
  const [state, setState] = useState<'idle' | 'busy' | 'sent'>('idle');
  const [error, setError] = useState('');
  const send = async () => {
    setState('busy');
    setError('');
    try {
      await filesApi.requestAccess(fileId, { purpose, reason });
      setState('sent');
    } catch (e) {
      setError(getErrorMessage(e));
      setState('idle');
    }
  };
  if (state === 'sent') return <Alert kind="success">Approval requested. Once the owner approves it under Access requests, try the download again.</Alert>;
  return (
    <div className="space-y-3 rounded-md border border-amber-400/40 p-3">
      <p className="text-sm text-amber-300">Ask the owner to approve this access.</p>
      {error && <Alert kind="error">{error}</Alert>}
      <Select label="Purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)}>
        {PURPOSES.map((p) => <option key={p} value={p}>{p}</option>)}
      </Select>
      <TextArea label="Reason (10+ characters)" value={reason} onChange={(e) => setReason(e.target.value)} />
      <Button onClick={send} loading={state === 'busy'} disabled={reason.trim().length < 10}>Request approval</Button>
    </div>
  );
}
