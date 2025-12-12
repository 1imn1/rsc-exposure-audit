#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import time
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
from urllib3.exceptions import InsecureRequestWarning

ACTION_RE = re.compile(r"[a-f0-9]{40,42}", re.IGNORECASE)

NEXT_HINTS = [
    "__NEXT_DATA__",
    "/_next/static/",
    "next-route-announcer",
]

RSC_HEADER_HINTS = [
    "rsc",
    "next-router-state-tree",
    "next-url",
    "next-action",
]

@dataclass
class ProbeResult:
    url: str
    status: Optional[int]
    elapsed_ms: int
    headers: Dict[str, str]
    snippet: str


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Black-box exposure check for React RSC / Next.js Server Actions (non-exploit)."
    )
    p.add_argument("target", help="Base URL (e.g. https://example.com/)")
    p.add_argument("--path", default="/", help="Path to probe (default: /)")
    p.add_argument("--timeout", type=int, default=15, help="Timeout seconds (default: 15)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--quiet-insecure", action="store_true", help="Suppress InsecureRequestWarning")
    return p.parse_args()


def norm_headers(h: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in h.items()}


def get(session: requests.Session, url: str, timeout: int, verify: bool, headers: Dict[str, str]) -> ProbeResult:
    start = time.time()
    try:
        r = session.get(url, timeout=timeout, verify=verify, headers=headers, allow_redirects=True)
        elapsed_ms = int((time.time() - start) * 1000)
        body = r.text or ""
        return ProbeResult(
            url=r.url,
            status=r.status_code,
            elapsed_ms=elapsed_ms,
            headers=dict(r.headers),
            snippet=body[:1200],
        )
    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return ProbeResult(url=url, status=None, elapsed_ms=elapsed_ms, headers={}, snippet=f"ERROR: {e}")


def detect_nextjs(html: str, headers: Dict[str, str]) -> List[str]:
    hits = []
    for hint in NEXT_HINTS:
        if hint in html:
            hits.append(f"html:{hint}")
    h = norm_headers(headers)
    if "x-powered-by" in h and "next" in h["x-powered-by"].lower():
        hits.append("header:x-powered-by(next)")
    if "server" in h and "next" in h["server"].lower():
        hits.append("header:server(next)")
    if any(k in h for k in ["x-nextjs-cache", "x-nextjs-page", "x-nextjs-matched-path"]):
        hits.append("header:x-nextjs-*")
    return hits


def detect_rsc_signals(headers: Dict[str, str], body: str) -> List[str]:
    hits = []
    h = norm_headers(headers)
    ct = h.get("content-type", "").lower()
    if "text/x-component" in ct:
        hits.append("content-type:text/x-component")

    for k in h.keys():
        if any(x in k for x in RSC_HEADER_HINTS):
            hits.append(f"header:{k}")

    # Very rough body hints (RSC payload lines often look like "0:[...]" "1:..." etc.)
    if re.search(r"^\d+:\s*[\[\{\"].*", body, flags=re.MULTILINE):
        hits.append("body:flight-like-lines")

    return sorted(set(hits))


def extract_action_ids(html: str) -> List[str]:
    matches = ACTION_RE.findall(html)
    # stable order, unique
    uniq = list(dict.fromkeys(matches))
    return uniq[:20]


def risk_assessment(next_hits: List[str], rsc_hits: List[str], action_ids: List[str]) -> Dict[str, str]:
    """
    Returns a conservative risk statement. This does NOT confirm vulnerability,
    only exposure/conditions suggesting urgent patching.
    """
    if not next_hits and not rsc_hits and not action_ids:
        return {
            "exposure": "low",
            "summary": "No clear Next.js/RSC signals detected on the probed path.",
            "action": "If you know this is a Next.js/RSC app, probe the correct route or check internally via SBOM/lockfiles.",
        }

    if rsc_hits or action_ids:
        return {
            "exposure": "high",
            "summary": "Signals of React Server Components / Server Actions exposure detected (RSC content-type/headers and/or actionId-like tokens).",
            "action": "Treat as at-risk for RSC advisories: patch/upgrade to safe versions and add compensating controls (rate limits, timeouts) immediately.",
        }

    return {
        "exposure": "medium",
        "summary": "Next.js signals detected, but no strong RSC/Server Actions indicators on this path.",
        "action": "Confirm whether App Router/RSC is enabled on other routes; if yes, patch according to advisories.",
    }


def main() -> None:
    args = parse_args()
    target = args.target.rstrip("/") + "/"
    probe_url = urljoin(target, args.path.lstrip("/"))

    verify = not args.insecure
    if args.insecure and args.quiet_insecure:
        warnings.simplefilter("ignore", InsecureRequestWarning)

    s = requests.Session()
    base_headers = {"User-Agent": "Mozilla/5.0"}

    print("=" * 80)
    print("RSC / Next.js Black-box Exposure Check (non-exploit)")
    print("=" * 80)
    print(f"Target: {target}")
    print(f"Probe : {probe_url}")
    print()

    # Probe normal GET
    r1 = get(s, probe_url, args.timeout, verify, base_headers)
    print(f"[GET]  status={r1.status} time={r1.elapsed_ms}ms final_url={r1.url}")

    next_hits = detect_nextjs(r1.snippet, r1.headers)
    action_ids = extract_action_ids(r1.snippet)

    # Probe "prefer RSC" GET (still safe; does not send Next-Action / does not POST)
    rsc_pref_headers = dict(base_headers)
    rsc_pref_headers.update({
        "Accept": "text/x-component,*/*;q=0.1",
        "RSC": "1",  # some stacks use this hint; harmless if ignored
    })
    r2 = get(s, probe_url, args.timeout, verify, rsc_pref_headers)
    print(f"[GET+RSC] status={r2.status} time={r2.elapsed_ms}ms final_url={r2.url}")

    rsc_hits = detect_rsc_signals(r2.headers, r2.snippet)

    print("\nSignals:")
    print(f"  Next.js hints: {', '.join(next_hits) if next_hits else 'none'}")
    print(f"  RSC hints    : {', '.join(rsc_hits) if rsc_hits else 'none'}")
    print(f"  Action IDs   : {len(action_ids)} {'(' + ', '.join(action_ids[:5]) + ('…' if len(action_ids) > 5 else '') + ')' if action_ids else ''}")

    risk = risk_assessment(next_hits, rsc_hits, action_ids)

    print("\nRisk (conservative):")
    print(f"  Exposure: {risk['exposure']}")
    print(f"  Summary : {risk['summary']}")
    print(f"  Action  : {risk['action']}")

    print("\nPatch guidance (reference):")
    print("  - CVE-2025-55182 (RCE) affects react-server-dom-* 19.0.0/19.1.0/19.1.1/19.2.0; patched in 19.0.1/19.1.2/19.2.1.")
    print("  - CVE-2025-55183 (source exposure) and CVE-2025-55184 (DoS), plus CVE-2025-67779 (incomplete fix): safe versions 19.0.3 / 19.1.4 / 19.2.3.")
    print("  - If you are on Vercel/Next.js, follow their React2Shell bulletin guidance.")
    print()

if __name__ == "__main__":
    main()
