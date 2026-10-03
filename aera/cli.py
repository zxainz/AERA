"""Command-line interface for AERA.

Commands:
    aera token --user U --domain D [--hours H]   mint an auth token
    aera analyze CVE-... [--vuln-type web]       single-CVE pipeline run
    aera batch cves.txt [--out DIR]             batch run from a file of CVE IDs
    aera dashboard DIR                          rebuild HTML dashboard from DIR/*.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from . import (
    AutonomousExploitResearchAssistant,
    BatchRunner,
    render_html_dashboard,
    summarize,
)


def _get_aera() -> AutonomousExploitResearchAssistant:
    load_dotenv()
    return AutonomousExploitResearchAssistant()


def cmd_token(args: argparse.Namespace) -> int:
    aera = _get_aera()
    token = aera.authorization.generate_token(
        user_id=args.user, domain=args.domain, hours=args.hours
    )
    print(token)
    aera.audit.log("token_minted_cli", args.user, domain=args.domain)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    async def _run() -> dict:
        load_dotenv()
        aera = AutonomousExploitResearchAssistant(
            sandbox_enabled=not args.no_sandbox
        )
        target_info = ""
        if args.target_info:
            target_info = args.target_info
        elif args.target_info_file:
            target_info = Path(args.target_info_file).read_text(encoding="utf-8")
        return await aera.process_vulnerability(
            args.cve_id, args.token, vuln_type=args.vuln_type,
            target_info=target_info,
        )

    result = asyncio.run(_run())
    out = Path(args.out or f"report-{args.cve_id}.md")
    out.write_text(result["report_markdown"], encoding="utf-8")
    print(f"Report written to {out}")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    cve_ids = [
        line.strip().upper()
        for line in Path(args.input).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not cve_ids:
        print("No CVE IDs found in input file.", file=sys.stderr)
        return 1

    async def _run() -> list[dict]:
        aera = _get_aera()
        runner = BatchRunner(
            aera, max_concurrency=args.concurrency, output_dir=args.out
        )
        return await runner.run(
            cve_ids, args.token,
            vuln_types={c: args.vuln_type for c in cve_ids},
        )

    results = asyncio.run(_run())
    ok = sum(1 for r in results if r["ok"])
    print(f"Done: {ok}/{len(results)} succeeded. Outputs in {args.out}/")
    summary = summarize(results)
    dashboard = render_html_dashboard(
        summary, results, Path(args.out) / "dashboard.html"
    )
    print(f"Dashboard: {dashboard}")
    return 0 if ok == len(results) else 2


def cmd_verify(args: argparse.Namespace) -> int:
    """Re-run a saved PoC to confirm a patch worked. No LLM needed."""

    async def _run() -> dict:
        load_dotenv()
        aera = AutonomousExploitResearchAssistant()
        return await aera.verify_fix(
            args.saved_json, args.token, vuln_type=args.vuln_type
        )

    result = asyncio.run(_run())
    print(f"CVE: {result['cve_id']}")
    print(f"Verdict: {result['verdict']}")
    print("--- stdout ---")
    print(result["test_result"].get("stdout", "")[:2000])
    return 0 if result["verdict"] == "not_vulnerable" else 1


def cmd_scan_code(args: argparse.Namespace) -> int:
    """Run the five-function codebase pipeline."""

    async def _run() -> dict:
        load_dotenv()
        aera = AutonomousExploitResearchAssistant()
        return await aera.analyze_codebase(
            args.path,
            args.token,
            target_cmd=args.target,
            fuzz=args.fuzz,
            iterations=args.iterations,
            llm_review=args.llm_review,
            image=args.image,
            engine=args.engine,
            sarif_path=args.sarif,
            grammar=args.grammar,
            coverage=args.coverage,
            pyfunc=args.pyfunc,
            dyn_verify=args.dyn_verify,
        )

    result = asyncio.run(_run())
    out = Path(args.out or "codebase-report.md")
    out.write_text(result["report_markdown"], encoding="utf-8")
    print(f"Files scanned: {result['stats']['files']}, "
          f"findings: {len(result['findings'])}")
    if args.fuzz or args.coverage:
        rep = sum(1 for c in result["crashes"] if c["reproducible"])
        print(f"Unique crashes: {len(result['crashes'])} ({rep} reproducible)")
        if result.get("coverage"):
            print(f"Lines covered: {result['coverage']['lines_covered']}")
    print(f"Report written to {out}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Continuous mode: rescan on an interval, report only what changed."""
    import time

    from .watch import scan_and_diff

    fail_on = {"critical": {"CRITICAL"}, "high": {"CRITICAL", "HIGH"},
               "medium": {"CRITICAL", "HIGH", "MEDIUM"}}[args.fail_on]
    iteration = 0
    while True:
        iteration += 1
        result = asyncio.run(scan_and_diff(
            args.path, args.token, args.state_file,
            engine=args.engine, fuzz=args.fuzz,
            target_cmd=args.target, iterations=args.iterations,
        ))
        new = result["new_findings"]
        fixed = result["fixed_findings"]
        print(f"[watch #{iteration}] findings: {len(result['findings'])} "
              f"(+{len(new)} new, -{len(fixed)} fixed)")
        for f in new:
            print(f"  NEW [{f['severity']}] {f['rule_id']} "
                  f"{f['file']}:{f['line']} — {f['title']}")
        for f in fixed:
            print(f"  FIXED [{f['severity']}] {f['rule_id']} "
                  f"{f['file']}:{f['line']}")
        bad = [f for f in new if f["severity"] in fail_on]
        if args.once:
            if bad:
                print(f"FAIL: {len(bad)} new finding(s) at/above {args.fail_on}")
                return 1
            print("OK: no new findings at/above threshold.")
            return 0
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nWatch stopped.")
            return 0


def cmd_build_asan(args: argparse.Namespace) -> int:
    """Compile C/C++ sources with AddressSanitizer + UBSan."""
    from .sanitizers import SanitizerError, build_with_sanitizers

    try:
        out = build_with_sanitizers(args.sources, args.o, compiler=args.cc)
    except SanitizerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Built sanitizer-instrumented binary: {out}")
    print("Fuzz it with: "
          f"aera scan-code <dir> --token <TOKEN> --fuzz --target {out}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Rebuild the dashboard from previously saved batch JSON files."""
    out_dir = Path(args.dir)
    results = []
    for path in sorted(out_dir.glob("CVE-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cve = data.get("cve") or {}
            results.append({
                "cve_id": cve.get("id", path.stem),
                "ok": True,
                "result": data,
            })
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Skipping {path.name}: {exc}", file=sys.stderr)
    if not results:
        print(f"No batch JSON files found in {out_dir}", file=sys.stderr)
        return 1
    summary = summarize(results)
    dashboard = render_html_dashboard(summary, results, out_dir / "dashboard.html")
    print(f"Dashboard rebuilt: {dashboard} ({summary['total']} CVEs)")
    return 0


def _require_token(aera: AutonomousExploitResearchAssistant, token: str) -> str:
    """Validate the token up-front; return the actor for audit purposes."""
    claims = aera.authorization.validate(token)
    return claims.get("sub", "unknown")


def cmd_recon(args: argparse.Namespace) -> int:
    """Map discovered versions (nmap XML or version list) to candidate CVEs."""
    from .recon import (parse_nmap_xml, parse_version_list, run_recon,
                        write_recon_outputs)

    aera = _get_aera()
    actor = _require_token(aera, args.token)
    inp = Path(args.input)
    if inp.suffix.lower() == ".xml":
        services = parse_nmap_xml(inp)
    else:
        services = parse_version_list(inp.read_text(encoding="utf-8"))
    if not services:
        print("No versioned services found in input.", file=sys.stderr)
        return 1
    print(f"Mapping {len(services)} service(s) to CVEs via NVD ...")
    results = run_recon(services)
    outs = write_recon_outputs(results, args.out)
    aera.audit.log("recon_done", actor, services=len(services),
                   cves=outs["cve_count"])
    print(f"Recon detail: {outs['recon_json']}")
    print(f"Candidate CVEs ({outs['cve_count']}): {outs['cves_txt']}")
    print("Next: aera batch " + outs["cves_txt"] + " --token <TOKEN> --out batch-out/")
    return 0


def cmd_webfuzz(args: argparse.Namespace) -> int:
    """Session-aware fuzzing of a web/API endpoint (authorized lab target)."""
    from .webfuzz import run_webfuzz

    aera = _get_aera()
    actor = _require_token(aera, args.token)
    params = [p.strip() for p in args.params.split(",") if p.strip()]
    if not params:
        print("No parameters to fuzz (--params q,page).", file=sys.stderr)
        return 1
    result = run_webfuzz(
        args.url, params, method=args.method, iterations=args.iterations,
        login_url=args.login_url, login_data=args.login_data,
        login_check=args.login_check, seed=args.seed,
    )
    aera.audit.log("webfuzz_done", actor, url=args.url,
                   findings=len(result["findings"]))
    out = Path(args.out or "webfuzz.json")
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Authenticated: {result['authenticated']}")
    print(f"Anomalies: {len(result['findings'])} -> {out}")
    for f in result["findings"][:10]:
        print(f"  [{f['severity']}] {f['kind']} on param "
              f"'{f['param']}': {f['evidence']}")
    return 0


def cmd_chains(args: argparse.Namespace) -> int:
    """Link findings/CVEs into candidate attack paths."""
    from .chains import (build_chains, nodes_from_cves, nodes_from_findings,
                         render_chains_markdown)

    aera = _get_aera()
    _require_token(aera, args.token)
    nodes: list[dict] = []
    if args.cve_dir:
        d = Path(args.cve_dir)
        results = []
        for path in sorted(d.glob("CVE-*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                results.append({"cve_id": path.stem, "ok": True, "result": data})
            except (json.JSONDecodeError, OSError):
                pass
        nodes += nodes_from_cves(results, scope=args.scope or "target")
    if args.sarif:
        data = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
        findings = []
        for run in data.get("runs", []):
            for r in run.get("results", []):
                loc = (r.get("locations") or [{}])[0].get(
                    "physicalLocation", {})
                findings.append({
                    "rule_id": r.get("ruleId", ""),
                    "title": r.get("message", {}).get("text", ""),
                    "severity": "HIGH",
                    "file": loc.get("artifactLocation", {}).get("uri", ""),
                    "line": (loc.get("region") or {}).get("startLine", 0),
                })
        nodes += nodes_from_findings(findings, scope=args.scope or "codebase")
    chains = build_chains(nodes)
    md = render_chains_markdown(chains)
    out = Path(args.out or "chains.md")
    out.write_text(md, encoding="utf-8")
    print(f"{len(chains)} candidate chain(s) from {len(nodes)} node(s) -> {out}")
    return 0


def cmd_kev_watch(args: argparse.Namespace) -> int:
    """Watch the CISA KEV feed for new entries matching the client stack."""
    import time

    from .kevwatch import check_kev

    aera = _get_aera()
    actor = _require_token(aera, args.token)
    iteration = 0
    while True:
        iteration += 1
        try:
            result = check_kev(args.stack, args.state)
        except Exception as exc:  # noqa: BLE001 - feed failures shouldn't kill the loop
            print(f"[kev-watch] feed error: {exc}", file=sys.stderr)
            if args.once:
                return 1
            time.sleep(args.interval)
            continue
        alerts = result["alerts"]
        aera.audit.log("kev_watch_cycle", actor, alerts=len(alerts))
        if alerts:
            print(f"[kev-watch] {len(alerts)} NEW KEV alert(s) matching your stack:")
            for a in alerts:
                print(f"  ! {a['cve_id']} -- {a['name']}")
                print(f"    {a['match_reason']}; action: {a['required_action']}")
        else:
            print(f"[kev-watch #{iteration}] no new KEV entries for this stack "
                  f"(feed total: {result['feed_total']}).")
        if args.once:
            return 0 if not alerts else 2
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nKEV watch stopped.")
            return 0


def cmd_client_report(args: argparse.Namespace) -> int:
    """Render a client-facing report (exec summary + roadmap) from batch JSON."""
    from .report_generator import render_client_report

    aera = _get_aera()
    _require_token(aera, args.token)
    d = Path(args.dir)
    results = []
    for path in sorted(d.glob("CVE-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cve = data.get("cve") or {}
            results.append({"cve_id": cve.get("id", path.stem),
                            "ok": True, "result": data})
        except (json.JSONDecodeError, OSError):
            pass
    if not results:
        print(f"No batch JSON files found in {d}", file=sys.stderr)
        return 1
    out = Path(args.out or "client-report.md")
    out.write_text(render_client_report(results), encoding="utf-8")
    print(f"Client report written to {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aera", description="Autonomous Exploit Research Assistant"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("token", help="Mint an authorization token")
    p.add_argument("--user", required=True, help="e.g. researcher@lab.example.com")
    p.add_argument("--domain", required=True, help="authorized research domain")
    p.add_argument("--hours", type=int, default=8)
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("analyze", help="Run the full pipeline for one CVE")
    p.add_argument("cve_id", help="e.g. CVE-2021-44228")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--vuln-type", default="auto",
                   choices=["auto", "web", "binary", "network"],
                   help="lab type; 'auto' infers from the CVE's CWEs")
    p.add_argument("--out", default=None, help="report path")
    p.add_argument("--no-sandbox", action="store_true",
                   help="analysis only: skip PoC generation and sandbox testing")
    p.add_argument("--target-info", default="",
                   help="tester-observed target facts (banner, headers, stack) "
                        "to tune the PoC, e.g. 'Server: Apache/2.4.49'")
    p.add_argument("--target-info-file", default=None,
                   help="read --target-info from a file")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("batch", help="Process many CVEs from a file")
    p.add_argument("input", help="text file with one CVE ID per line")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--out", default="batch-out")
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--vuln-type", default="auto",
                   choices=["auto", "web", "binary", "network"])
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("verify",
                       help="Re-run a saved PoC to confirm a patch worked")
    p.add_argument("saved_json", help="batch-output JSON, e.g. batch-out/CVE-2021-44228.json")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--vuln-type", default="auto",
                   choices=["auto", "web", "binary", "network"])
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("scan-code",
                       help="Five-function pipeline over a local source tree")
    p.add_argument("path", help="local source directory (must be authorized)")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--fuzz", action="store_true",
                   help="run a sandboxed fuzz campaign after static scan")
    p.add_argument("--target", nargs="+", default=None,
                   help='how to run the target, e.g. --target ./vuln  OR '
                        '--target python3 harness.py "{input}"')
    p.add_argument("--iterations", type=int, default=200,
                   help="fuzz iterations (default 200)")
    p.add_argument("--llm-review", action="store_true",
                   help="LLM deep-review of top static findings")
    p.add_argument("--image", default=None,
                   help="sandbox image for fuzzing (default: binary lab image)")
    p.add_argument("--out", default=None, help="report path")
    p.add_argument("--engine", default="auto",
                   choices=["auto", "semgrep", "regex"],
                   help="static analysis engine")
    p.add_argument("--sarif", default=None,
                   help="also write findings+crashes as SARIF 2.1.0")
    p.add_argument("--grammar", default=None, choices=["json", "http"],
                   help="seed campaign with structured inputs")
    p.add_argument("--coverage", action="store_true",
                   help="coverage-guided in-process fuzzing (needs --pyfunc, Python 3.12+)")
    p.add_argument("--pyfunc", default=None,
                   help='Python function target, e.g. "mypkg.parser:parse"')
    p.add_argument("--dyn-verify", action="store_true",
                   help="dynamically confirm top static findings with "
                        "sandbox trigger scripts (needs Docker + LLM)")
    p.set_defaults(func=cmd_scan_code)

    p = sub.add_parser("watch",
                       help="rescan on an interval; report only what changed")
    p.add_argument("path", help="local source directory")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--interval", type=int, default=300,
                   help="seconds between scans (default 300)")
    p.add_argument("--once", action="store_true",
                   help="single scan (CI mode); exit 1 on new findings")
    p.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium"],
                   help="severity threshold for --once failure")
    p.add_argument("--state-file", default=".aera-state.json",
                   help="where to keep the last-run state")
    p.add_argument("--engine", default="auto",
                   choices=["auto", "semgrep", "regex"])
    p.add_argument("--fuzz", action="store_true")
    p.add_argument("--target", nargs="+", default=None)
    p.add_argument("--iterations", type=int, default=200)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("build-asan",
                       help="compile C/C++ with AddressSanitizer+UBSan")
    p.add_argument("sources", nargs="+", help="C/C++ source files")
    p.add_argument("-o", required=True, help="output binary path")
    p.add_argument("--cc", default=None, help="compiler (default: clang or gcc)")
    p.set_defaults(func=cmd_build_asan)

    p = sub.add_parser("dashboard", help="Rebuild dashboard from saved batch JSON")
    p.add_argument("dir", help="batch output directory")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("recon",
                       help="map discovered versions to candidate CVEs")
    p.add_argument("input", help="nmap XML file or text version list")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--out", default="recon-out",
                   help="output dir (recon.json + cves.txt)")
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("webfuzz",
                       help="session-aware fuzzing of a web/API endpoint")
    p.add_argument("--url", required=True,
                   help="endpoint to fuzz (authorized lab target)")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--params", required=True,
                   help="comma-separated parameter names, e.g. 'q,page'")
    p.add_argument("--iterations", type=int, default=200)
    p.add_argument("--login-url", default=None, help="form login URL")
    p.add_argument("--login-data", default="",
                   help="login form fields, e.g. 'user=u&pass=p' "
                        "(prefer env-sourced values for lab creds)")
    p.add_argument("--login-check", default="",
                   help="string proving login worked, e.g. 'Logout'")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", default=None, help="JSON output path")
    p.set_defaults(func=cmd_webfuzz)

    p = sub.add_parser("chains",
                       help="link findings/CVEs into candidate attack paths")
    p.add_argument("--cve-dir", default=None, help="batch output directory")
    p.add_argument("--sarif", default=None, help="SARIF file from scan-code")
    p.add_argument("--scope", default="target", help="node scope label")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--out", default=None, help="markdown output path")
    p.set_defaults(func=cmd_chains)

    p = sub.add_parser("kev-watch",
                       help="alert when new KEV entries hit your client stack")
    p.add_argument("--stack", required=True,
                   help='JSON stack file: {"products": [...], "cves": [...]}')
    p.add_argument("--state", default=".kev-state.json",
                   help="state file for last-check tracking")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--once", action="store_true",
                   help="single check; exit 2 if alerts fired")
    p.add_argument("--interval", type=int, default=86400,
                   help="seconds between checks (default 86400)")
    p.set_defaults(func=cmd_kev_watch)

    p = sub.add_parser("client-report",
                       help="client-facing report from saved batch JSON")
    p.add_argument("dir", help="batch output directory")
    p.add_argument("--token", required=True, help="authorization token")
    p.add_argument("--out", default=None, help="markdown output path")
    p.set_defaults(func=cmd_client_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
