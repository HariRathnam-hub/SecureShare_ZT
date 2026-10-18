import http from 'http';
import type { Express } from 'express';

export interface Res { status: number; headers: http.IncomingHttpHeaders; body: string; json: any }

/** Starts an Express app on an ephemeral port and returns a tiny request helper. */
export function serve(app: Express) {
  const server = http.createServer(app).listen(0);
  const port = (server.address() as any).port;
  const call = (method: string, path: string, opts: { headers?: http.OutgoingHttpHeaders; body?: unknown } = {}) =>
    new Promise<Res>((resolve, reject) => {
      const payload = opts.body === undefined ? undefined : typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
      const headers: http.OutgoingHttpHeaders = { ...(payload !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}), ...opts.headers };
      const r = http.request({ port, path, method, headers }, (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => { let json: any; try { json = JSON.parse(b); } catch { /* not json */ } resolve({ status: res.statusCode!, headers: res.headers, body: b, json }); });
      });
      r.on('error', reject);
      r.end(payload);
    });
  return { call, close: () => server.close() };
}
