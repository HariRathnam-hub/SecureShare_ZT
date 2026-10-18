import { ReactNode } from 'react';

export default function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main className="grid min-h-screen lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <aside className="hidden flex-col justify-between border-r border-line bg-panel p-12 lg:flex">
        <p className="text-lg font-semibold tracking-tight">SecureShare ZT</p>
        <div className="max-w-sm">
          <p className="text-3xl font-semibold leading-snug">Every request proves who it is. Every file earns its access.</p>
          <p className="mt-4 text-sm leading-relaxed text-mute">
            Identity is checked on each call, sessions rotate on use, and nothing is trusted because it came from inside.
          </p>
        </div>
        <p className="text-xs text-mute">Zero Trust file sharing</p>
      </aside>
      <section className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <h1 className="text-2xl font-semibold">{title}</h1>
          {subtitle && <p className="mt-2 text-sm text-mute">{subtitle}</p>}
          <div className="mt-8">{children}</div>
        </div>
      </section>
    </main>
  );
}
