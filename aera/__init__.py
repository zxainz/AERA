"""AERA: Autonomous Exploit Research Assistant.

For authorized defensive security research only. See docs/ETHICAL_USAGE.md.
"""
from .batch import BatchRunner
from .chains import build_chains, nodes_from_cves, nodes_from_findings
from .codebase import CodebaseTarget
from .core import AutonomousExploitResearchAssistant, build_poc_prompt
from .coverage import run_coverage_campaign
from .dynverify import parse_trigger_verdict, verify_findings
from .fuzz import SandboxFuzzRunner, run_campaign, seeds_for_findings
from .grammar import GENERATORS, run_grammar_campaign
from .intel import KEVCatalog, enrich
from .kevwatch import check_kev
from .llm import provider_from_env
from .minimize import classify_severity, minimize
from .patterns import render_html_dashboard, summarize
from .recon import (candidate_cves, parse_nmap_xml, parse_version_list,
                    run_recon)
from .report_generator import (generate_executive_summary, impact_statement,
                               render_client_report)
from .sandbox import parse_run_output
from .sanitizers import build_with_sanitizers, parse_sanitizer_report
from .sarif import findings_to_sarif, write_sarif
from .semgrep import semgrep_available
from .static import scan_codebase
from .triage import dedupe, reproduce
from .utils import detect_vuln_type
from .watch import diff_findings
from .webfuzz import run_webfuzz

__all__ = [
    "AutonomousExploitResearchAssistant",
    "BatchRunner",
    "CodebaseTarget",
    "KEVCatalog",
    "SandboxFuzzRunner",
    "build_chains",
    "build_poc_prompt",
    "build_with_sanitizers",
    "candidate_cves",
    "check_kev",
    "classify_severity",
    "dedupe",
    "detect_vuln_type",
    "diff_findings",
    "enrich",
    "findings_to_sarif",
    "generate_executive_summary",
    "impact_statement",
    "minimize",
    "nodes_from_cves",
    "nodes_from_findings",
    "parse_nmap_xml",
    "parse_run_output",
    "parse_sanitizer_report",
    "parse_trigger_verdict",
    "parse_version_list",
    "provider_from_env",
    "render_client_report",
    "render_html_dashboard",
    "reproduce",
    "run_campaign",
    "run_coverage_campaign",
    "run_grammar_campaign",
    "run_recon",
    "run_webfuzz",
    "scan_codebase",
    "seeds_for_findings",
    "semgrep_available",
    "summarize",
    "verify_findings",
    "write_sarif",
]
__version__ = "0.6.0"
