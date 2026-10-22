export type Verdict = "risk" | "patched" | "clear" | "hidden" | "error";

export type CheckReport = {
  verdict: Verdict;
  checkedUrl: string;
  finalUrl: string;
  headline: string;
  detail: string;
  signals: string[];
  sell: string;
  hostNote: string;
};

export const FIXED_VERSIONS = "8.2.35, 8.3.36, 8.4.27 or 8.5.12";

export function hostNoteFor(domain: string) {
  return `Please confirm in writing the PHP version or Linux package serving ${domain}, and whether CVE-2026-109618 and CVE-2026-109619 are patched. Upstream fixes are PHP ${FIXED_VERSIONS}. If you are on a vendor package, send the full package version, not just the PHP branch. Confirm PHP was restarted after the update. Updating WordPress, plugins or themes does not fix this.`;
}

export function coldEmail(domain = "[their domain]") {
  return `Subject: Your website and today's PHP emergency

Hi [name],

Two critical flaws in PHP were patched yesterday and are already being attacked. They sit in the language on the server, so updating WordPress does not close them.

I can tell you today whether ${domain} looks like it is running PHP, and if it is, the exact question to send your host. If they cannot patch quickly, I can move the site onto hosting that does not run PHP.

Same-day written check: £149. Moving the site off PHP starts at £900.

Paul McWilliam`;
}

export function callScript() {
  return `The bug is in PHP itself, not in the website design. Updating the theme does nothing.

I need your host to confirm the PHP package and that they restarted PHP after yesterday's patch. I can send them the question.

If they cannot confirm it today, the safe move is to take the old site off the internet or put it somewhere that does not run PHP. I can do that this week.`;
}
