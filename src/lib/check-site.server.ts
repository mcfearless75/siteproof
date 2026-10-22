import { lookup } from "node:dns/promises";
import type { CheckReport, Verdict } from "./check-types";
import { hostNoteFor } from "./check-types";

const HITS: { at: number }[] = [];

function allowRequest() {
  const now = Date.now();
  while (HITS.length && now - HITS[0].at > 60_000) HITS.shift();
  if (HITS.length >= 24) return false;
  HITS.push({ at: now });
  return true;
}

function blockedIp(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower.startsWith("::ffff:")) return blockedIp(lower.slice(7));
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (lower.startsWith("2001:db8")) return true;
  if (lower.includes(":")) return false;

  if (/[a-z]/i.test(lower)) return false;

  const parts = lower.split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function blockedHost(hostname: string) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost")) return true;
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localdomain")) return true;
  if (host === "metadata.google.internal" || host.includes("metadata.google")) return true;
  return false;
}

class CheckError extends Error {
  report: CheckReport;
  constructor(checkedUrl: string, detail: string) {
    super(detail);
    this.report = {
      verdict: "error",
      checkedUrl,
      finalUrl: checkedUrl,
      headline: "Could not check that address",
      detail,
      signals: [],
      sell: "Ask them for the public web address, then run it again.",
      hostNote: "",
    };
  }
}

function parseStart(raw: string): URL {
  let s = raw.trim();
  if (!s) throw new CheckError("", "Paste the public web address.");
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    throw new CheckError(raw.trim(), "That does not look like a web address.");
  }
  if (url.username || url.password) {
    throw new CheckError(url.hostname, "Remove any username or password from the address.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new CheckError(url.hostname, "Only a normal http or https website can be checked.");
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new CheckError(url.hostname, "This check only looks at the public site on port 80 or 443.");
  }
  if (blockedHost(url.hostname) || blockedIp(url.hostname)) {
    throw new CheckError(url.hostname, "That address is not a public website.");
  }
  url.hash = "";
  return url;
}

async function assertPublic(url: URL) {
  if (blockedHost(url.hostname) || blockedIp(url.hostname)) {
    throw new CheckError(url.hostname, "That address is not a public website.");
  }
  let records: { address: string }[];
  try {
    records = await lookup(url.hostname, { all: true, verbatim: true });
  } catch {
    throw new CheckError(url.hostname, "Could not find that site. Check the spelling.");
  }
  if (!records.length || records.some((r) => blockedIp(r.address))) {
    throw new CheckError(url.hostname, "That address is not a public website.");
  }
}

type PhpState = "none" | "risk" | "patched" | "eol";

function phpState(header: string): { state: PhpState; label: string | null } {
  const match = header.match(/php\/(\d+)\.(\d+)\.(\d+)/i);
  if (!match && /php/i.test(header)) {
    return { state: "risk", label: `Server names PHP (${header.slice(0, 80)}) but not a full version.` };
  }
  if (!match) return { state: "none", label: null };
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  const shown = `${major}.${minor}.${patch}`;
  if (major > 8 || (major === 8 && minor >= 6)) {
    return { state: "patched", label: `Server reports PHP ${shown}, newer than the patched branches.` };
  }
  if (major === 8 && minor === 5 && patch >= 12) return { state: "patched", label: `Server reports PHP ${shown}, which includes the fix.` };
  if (major === 8 && minor === 4 && patch >= 27) return { state: "patched", label: `Server reports PHP ${shown}, which includes the fix.` };
  if (major === 8 && minor === 3 && patch >= 36) return { state: "patched", label: `Server reports PHP ${shown}, which includes the fix.` };
  if (major === 8 && minor === 2 && patch >= 35) return { state: "patched", label: `Server reports PHP ${shown}, which includes the fix.` };
  if (major === 8 && minor >= 2) {
    return { state: "risk", label: `Server reports PHP ${shown}, older than the fix for that branch.` };
  }
  return {
    state: "eol",
    label: `Server reports PHP ${shown}. Upstream no longer patches that branch. Only a Linux vendor backport would count, and this header cannot prove it.`,
  };
}

function cookieHits(raw: string) {
  const hits: string[] = [];
  const known = ["PHPSESSID", "laravel_session", "wordpress_", "wp-settings", "wp_woocommerce"];
  for (const name of known) {
    if (raw.toLowerCase().includes(name.toLowerCase())) hits.push(name);
  }
  return hits;
}

function classify(finalUrl: string, status: number, headers: Headers, html: string): Omit<CheckReport, "checkedUrl" | "hostNote"> {
  const signals: string[] = [];
  const powered = headers.get("x-powered-by") ?? "";
  const server = headers.get("server") ?? "";
  const cookies = headers.get("set-cookie") ?? "";
  const lower = html.toLowerCase();
  const php = phpState(powered);
  if (php.label) signals.push(php.label);

  const cookieNames = cookieHits(cookies);
  if (cookieNames.length) signals.push(`Response sets a PHP-style cookie (${cookieNames.join(", ")}). Values were not stored.`);

  if (lower.includes("wp-content") || lower.includes("wp-includes") || lower.includes("/wp-json")) {
    signals.push("Page markup looks like WordPress.");
  }
  const generator = html.match(/<meta[^>]*name=["']generator["'][^>]*>/i)?.[0] ?? "";
  const genContent = (generator.match(/content=["']([^"']+)["']/i)?.[1] ?? generator).slice(0, 120);
  if (/wordpress/i.test(genContent) || /joomla/i.test(genContent) || /drupal/i.test(lower.slice(0, 8000))) {
    if (/wordpress/i.test(genContent)) signals.push("Generator tag says WordPress.");
    else if (/joomla/i.test(genContent)) signals.push("Generator tag says Joomla.");
    else if (lower.includes("drupal")) signals.push("Page looks like Drupal.");
  }

  const platform: string[] = [];
  if (/wix\.com/i.test(genContent) || lower.includes("wixstatic.com") || lower.includes("x-wix-")) {
    platform.push("Wix");
  }
  if (/squarespace/i.test(genContent)) platform.push("Squarespace");
  if (/webflow/i.test(genContent)) platform.push("Webflow");
  if (lower.includes("cdn.shopify.com") || headers.get("x-shopid")) platform.push("Shopify");
  if (/^github\.com$/i.test(server) || /github\.io$/i.test(new URL(finalUrl).hostname)) platform.push("GitHub Pages");
  if (/vercel/i.test(server) || /next\.js/i.test(powered)) platform.push("Vercel / Next.js");
  if (/netlify/i.test(server)) platform.push("Netlify");
  if (platform.length) signals.push(`Hosting looks like ${platform.join(", ")}, which does not run the customer's PHP.`);

  const phpMarkup =
    signals.some((s) => /wordpress|joomla|drupal|php-style cookie/i.test(s)) || php.state === "risk" || php.state === "eol";

  let verdict: Verdict = "hidden";
  if (php.state === "patched" && !signals.some((s) => /wordpress|joomla|drupal/i.test(s))) {
    verdict = "patched";
  } else if (phpMarkup || php.state === "risk" || php.state === "eol") {
    verdict = "risk";
  } else if (platform.length) {
    verdict = "clear";
  }

  const host = new URL(finalUrl).hostname;
  if (verdict === "risk") {
    return {
      verdict,
      finalUrl,
      headline: `${host} looks like it is on PHP`,
      detail:
        "The homepage gave off PHP or a PHP app such as WordPress. Updating that app does not fix yesterday's bugs. The host has to patch PHP and restart it, or the site has to leave PHP.",
      signals: [`HTTP ${status}`, ...signals],
      sell: "Sell the £149 written check today. If the host cannot confirm a patched package, quote from £900 to move the site off PHP this week.",
    };
  }
  if (verdict === "patched") {
    return {
      verdict,
      finalUrl,
      headline: `${host} reports a patched PHP version`,
      detail:
        "The version string is at or above the fix. Headers can be stale or sitting on a proxy. Still get the host to confirm the package and that PHP was restarted. Do not tell the client they are safe on this alone.",
      signals: [`HTTP ${status}`, ...signals],
      sell: "Charge the £149 to turn this into a written note. Do not quote a rebuild unless they want off PHP anyway.",
    };
  }
  if (verdict === "clear") {
    return {
      verdict,
      finalUrl,
      headline: `${host} does not look like customer PHP`,
      detail:
        "This page is on a platform that hosts the site for them. PHP2Shell does not apply to that setup. Do not send them a scare email.",
      signals: [`HTTP ${status}`, ...signals],
      sell: "Skip them for this offer. A scare email will cost you the relationship.",
    };
  }
  const front = /cloudflare/i.test(server) ? "Cloudflare is in front, which hides the origin. " : "";
  const stack = /apache|nginx|litespeed|openresty/i.test(server)
    ? `The server header says ${server.slice(0, 60)}, which often sits in front of PHP. `
    : "";
  return {
    verdict: "hidden",
    finalUrl,
    headline: `${host} is not showing its stack`,
    detail: `${front}${stack}Nothing on the homepage proves PHP, and nothing proves it is a static host either. This is the paid check: ask the host, do not guess.`,
    signals: [`HTTP ${status}`, ...signals, "No PHP version and no known safe platform on the homepage."],
    sell: "This is the £149. You cannot clear them from the outside. Send the host question and charge for the written answer.",
  };
}

async function readLimited(res: Response) {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  const cap = 48_000;
  while (total < cap) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value);
    total += value.byteLength;
  }
  await reader.cancel().catch(() => undefined);
  const buf = new Uint8Array(Math.min(total, cap));
  let offset = 0;
  for (const chunk of chunks) {
    const take = Math.min(chunk.byteLength, buf.byteLength - offset);
    if (take <= 0) break;
    buf.set(chunk.subarray(0, take), offset);
    offset += take;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

export async function runCheck(raw: string): Promise<CheckReport> {
  if (!allowRequest()) {
    return {
      verdict: "error",
      checkedUrl: raw.trim(),
      finalUrl: "",
      headline: "Slow down for a minute",
      detail: "Too many checks in the last minute. Wait, then run the next site.",
      signals: [],
      sell: "",
      hostNote: "",
    };
  }

  let current: URL;
  try {
    current = parseStart(raw);
  } catch (err) {
    if (err instanceof CheckError) return err.report;
    throw err;
  }

  const checkedUrl = current.toString();
  try {
    for (let hop = 0; hop < 4; hop++) {
      await assertPublic(current);
      const res = await fetch(current, {
        method: "GET",
        redirect: "manual",
        headers: {
          "user-agent": "Siteproof/1.0 (passive homepage check; not a security scan)",
          accept: "text/html,application/xhtml+xml",
        },
        signal: AbortSignal.timeout(8000),
      });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        await res.body?.cancel().catch(() => undefined);
        if (!loc) break;
        current = new URL(loc, current);
        if (current.protocol !== "http:" && current.protocol !== "https:") {
          throw new CheckError(checkedUrl, "The site redirected somewhere that is not a normal web page.");
        }
        continue;
      }
      const html = await readLimited(res);
      const report = classify(current.toString(), res.status, res.headers, html);
      const domain = new URL(report.finalUrl).hostname;
      return { ...report, checkedUrl, hostNote: hostNoteFor(domain) };
    }
    throw new CheckError(checkedUrl, "The site redirected too many times.");
  } catch (err) {
    if (err instanceof CheckError) return { ...err.report, checkedUrl };
    const aborted = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
    return {
      verdict: "error",
      checkedUrl,
      finalUrl: current.toString(),
      headline: aborted ? "The site did not answer in time" : "The site did not answer",
      detail: aborted
        ? "Eight seconds was not enough. Try again, or ask them which address customers actually use."
        : "The connection failed. Check the address, or ask them for the public URL.",
      signals: [],
      sell: "If it only fails from here, call them and ask who hosts it.",
      hostNote: hostNoteFor(current.hostname),
    };
  }
}
