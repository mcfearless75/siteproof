import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState, type FormEvent, type ReactNode } from "react";
import { AlertTriangle, Check, Copy, Phone, ShieldCheck } from "lucide-react";
import { checkSite } from "@/lib/check-site";
import { callScript, coldEmail, type CheckReport, type Verdict } from "@/lib/check-types";

export const Route = createFileRoute("/")({ component: Home });

const tone: Record<Verdict, { bg: string; fg: string; label: string }> = {
  risk: { bg: "bg-risk-bg", fg: "text-risk", label: "On PHP" },
  patched: { bg: "bg-wait-bg", fg: "text-wait", label: "Version looks patched" },
  clear: { bg: "bg-safe-bg", fg: "text-safe", label: "Not this bug" },
  hidden: { bg: "bg-wait-bg", fg: "text-wait", label: "Ask the host" },
  error: { bg: "bg-card", fg: "text-ink", label: "No result" },
};

function Home() {
  const run = useServerFn(checkSite);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<CheckReport | null>(null);
  const [formError, setFormError] = useState("");

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setBusy(true);
    try {
      const next = await run({ data: { url } });
      setReport(next);
    } catch {
      setFormError("The check failed before it reached the site. Try the address again.");
    } finally {
      setBusy(false);
    }
  }

  const domain = report?.finalUrl ? safeHost(report.finalUrl) : "[their domain]";

  return (
    <main className="mx-auto w-full max-w-5xl px-4 py-6 sm:px-6 sm:py-10">
      <header className="flex items-baseline justify-between gap-4 border-b border-line pb-4">
        <p className="font-display text-2xl tracking-tight">Siteproof</p>
        <p className="text-sm text-muted">Same-day PHP check · Paul McWilliam</p>
      </header>

      <section className="mt-8 grid gap-8 lg:grid-cols-[1.15fr_0.85fr] lg:items-start">
        <div>
          <p className="text-sm font-medium tracking-wide text-copper uppercase">Use this before you call</p>
          <h1 className="font-display mt-2 text-4xl leading-tight text-balance sm:text-5xl">
            Is their live site on the PHP that broke today?
          </h1>
          <p className="mt-4 max-w-xl text-lg text-muted">
            One ordinary homepage load. No exploit, no login, no password guessing. You get a verdict and the sentence to send their host.
          </p>

          <form onSubmit={onSubmit} className="mt-6 flex flex-col gap-3 sm:flex-row">
            <label className="sr-only" htmlFor="site-url">
              Website address
            </label>
            <input
              id="site-url"
              name="url"
              inputMode="url"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="theirbusiness.co.uk"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="min-h-12 flex-1 rounded-card border border-line bg-card px-4 text-base text-ink outline-none ring-copper/40 placeholder:text-muted focus:ring-2"
            />
            <button
              type="submit"
              disabled={busy || url.trim().length < 3}
              className="min-h-12 rounded-card bg-ink px-5 text-base font-medium text-paper disabled:opacity-50"
            >
              {busy ? "Checking…" : "Check the live site"}
            </button>
          </form>
          {formError ? <p className="mt-3 text-sm text-risk">{formError}</p> : null}
          <p className="mt-3 text-sm text-muted">Only check a site you are allowed to look at. This is not a penetration test.</p>
        </div>

        <aside className="rounded-card border border-line bg-card p-5">
          <p className="text-sm font-medium text-muted">Do not mail these</p>
          <ul className="mt-3 space-y-2 text-sm">
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-safe" aria-hidden /> Wix, Shopify, Squarespace, Webflow</li>
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-safe" aria-hidden /> GitHub Pages, Netlify, Vercel, Next.js</li>
            <li className="flex gap-2"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-wait" aria-hidden /> WordPress, cPanel, SiteGround, GoDaddy, 1&1</li>
          </ul>
          <p className="mt-4 text-sm text-muted">
            A scare email to someone already off PHP costs you the client. Call the WordPress and shared-hosting list.
          </p>
        </aside>
      </section>

      {report ? <ReportCard report={report} /> : null}

      <section className="mt-12" aria-labelledby="kit-title">
        <h2 id="kit-title" className="font-display text-3xl">Send tonight</h2>
        <p className="mt-2 max-w-2xl text-muted">
          Copy, change the name, send. Prices are the ones to quote until you decide otherwise.
        </p>
        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          <KitCard title="Email" body={coldEmail(domain)} />
          <KitCard title="If they pick up" body={callScript()} icon={<Phone className="size-4" aria-hidden />} />
          <article className="flex flex-col rounded-card border border-line bg-card p-5">
            <h3 className="font-medium">What to charge</h3>
            <dl className="mt-4 space-y-4">
              <div>
                <dt className="font-display text-3xl">£149</dt>
                <dd className="text-sm text-muted">Same day. You check the live site and send the host question. They get a short written note.</dd>
              </div>
              <div>
                <dt className="font-display text-3xl">from £900</dt>
                <dd className="text-sm text-muted">This week. Move the site off PHP onto static hosting. Only if the host cannot show a patched package.</dd>
              </div>
            </dl>
            <p className="mt-4 text-sm text-muted">Fixed upstream releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Older PHP is only safe if the Linux vendor backported both fixes and restarted PHP.</p>
          </article>
        </div>
      </section>

      <footer className="mt-12 border-t border-line pt-4 text-sm text-muted">
        PHP2Shell is CVE-2026-109618 and CVE-2026-109619. The patch is on the server, not in the theme.
      </footer>
    </main>
  );
}

function ReportCard({ report }: { report: CheckReport }) {
  const t = tone[report.verdict];
  return (
    <section className={`mt-8 rounded-card border border-line p-5 sm:p-6 ${t.bg}`} aria-live="polite">
      <p className={`text-sm font-medium ${t.fg}`}>{t.label}</p>
      <h2 className="font-display mt-1 text-3xl text-balance">{report.headline}</h2>
      <p className="mt-3 max-w-3xl text-ink">{report.detail}</p>
      {report.sell ? <p className="mt-3 max-w-3xl font-medium">{report.sell}</p> : null}
      {report.signals.length ? (
        <ul className="mt-4 space-y-1 text-sm text-ink">
          {report.signals.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      ) : null}
      {report.hostNote && report.verdict !== "clear" ? (
        <div className="mt-5">
          <KitCard title="Question for their host" body={report.hostNote} />
        </div>
      ) : null}
    </section>
  );
}

function KitCard({ title, body, icon }: { title: string; body: string; icon?: ReactNode }) {
  return (
    <article className="flex flex-col rounded-card border border-line bg-card p-5">
      <div className="flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 font-medium">
          {icon}
          {title}
        </h3>
        <CopyButton text={body} />
      </div>
      <pre className="mt-4 whitespace-pre-wrap font-sans text-sm leading-relaxed text-ink">{body}</pre>
    </article>
  );
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex min-h-11 items-center gap-1 rounded-card border border-line bg-paper px-3 text-sm text-ink"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          window.setTimeout(() => setDone(false), 1600);
        } catch {
          setDone(false);
        }
      }}
    >
      {done ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function safeHost(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}
