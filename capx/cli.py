import argparse
import sys
from capx import __version__
from capx.logging_config import logger

def handle_inspect(args: argparse.Namespace) -> None:
    """Routes the inspect command to the API/Application layer."""
    logger.info("Initiating CAPX Inspect Mode...")
    print("[*] Initiating CAPX Core Inspection Pipeline...\n")
    
    from capx.api.inspector import InspectEngine
    engine = InspectEngine()
    results = engine.run_full_inspection()
    
    # --- 1. System Health ---
    sys_facts = results.get("system_facts", {})
    if sys_facts.get("status") == "success":
        print("=== SYSTEM HEALTH ===")
        print(f"OS: {sys_facts['os']['system']} {sys_facts['os']['release']}")
        print(f"CPU Usage: {sys_facts['cpu']['usage_percent']}%")
        print(f"Memory Usage: {sys_facts['memory']['usage_percent']}%\n")
        
    # --- 2. Process Analysis ---
    proc_findings = results.get("process_findings", {})
    if proc_findings.get("status") == "success":
        print(f"=== PROCESS ANALYSIS ({proc_findings['analyzed_count']} processes analyzed) ===")
        findings = proc_findings.get("findings", [])
        if not findings:
            print("[+] No process anomalies detected.")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['type']} | {f['source']} -> {f['details']}")

    # --- 3. Network Analysis ---
    net_findings = results.get("network_findings", {})
    if net_findings.get("status") == "success":
        print(f"\n=== NETWORK ANALYSIS ({net_findings['analyzed_count']} connections analyzed) ===")
        findings = net_findings.get("findings", [])
        if not findings:
            print("[+] No anomalous network exposure detected.")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['type']} | {f['source']} -> {f['details']}")

    # --- 4. Startup & Persistence ---
    startup_findings = results.get("startup_findings", {})
    if startup_findings.get("status") == "success":
        print(f"\n=== STARTUP & PERSISTENCE ({startup_findings['analyzed_count']} items analyzed) ===")
        findings = startup_findings.get("findings", [])
        if not findings:
            print("[+] No suspicious startup anomalies detected.")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['type']} | {f['source']} -> {f['details']}")

    # --- 5. Detection Engine Alerts ---
    detection = results.get("detection_alerts", {})
    if detection.get("status") == "success":
        print(f"\n=== DETECTION ENGINE ({detection['alerts_count']} correlated alerts) ===")
        alerts = detection.get("alerts", [])
        if not alerts:
            print("[+] No correlated behavioral anomalies detected.")
        else:
            for a in alerts:
                print(f"[{a['severity']}] {a['type']} | {a['source']} -> {a['details']}")
                
    # --- 6. Risk Assessment ---
    risk = results.get("risk_assessment", {})
    if risk.get("status") == "success":
        print(f"\n=== OVERALL SYSTEM RISK ===")
        print(f"Risk Score: {risk['score']}/100")
        print(f"Risk Band:  [{risk['band']}]")
        print(f"Total Issues Evaluated: {risk['total_issues_evaluated']}")
        
    # --- 7. Actionable Recommendations ---
    recs = results.get("recommendations", {})
    if recs.get("status") == "success" and recs.get("count", 0) > 0:
        print(f"\n=== ACTIONABLE RECOMMENDATIONS ({recs['count']}) ===")
        for r in recs.get("recommendations", []):
            print(f"[{r['priority']}] TARGET: {r['target']}")
            print(f"    -> ACTION: {r['action']}")

    # --- 8. Export Functionality ---
    if getattr(args, 'export', False):
        from capx.core.reporting.exporter import ReportExporter
        exporter = ReportExporter()
        path = exporter.export_json(results)
        if path:
            print(f"\n[+] Full JSON report exported to: {path}")
        else:
            print("\n[-] Failed to export report. Check logs.")

    print("\n[*] Inspection Complete.")


def handle_monitor(args: argparse.Namespace) -> None:
    """Routes the monitor command to the Monitoring Engine."""
    from capx.monitoring.monitor import MonitorEngine
    
    # We can default to 10 seconds for testing purposes
    monitor = MonitorEngine(interval_seconds=10)
    monitor.start_monitoring()


def handle_optimize(args: argparse.Namespace) -> None:
    """Routes the optimize command to guided remediation."""
    import re
    from capx.api.inspector import InspectEngine
    from capx.core.optimization.optimizer import SafeOptimizer
    
    print("[*] Initiating CAPX Guided Optimization Mode...")
    print("[*] Scanning system for optimizable targets (this takes a moment)...\n")
    
    engine = InspectEngine()
    optimizer = SafeOptimizer()
    
    # 1. Analyze & Identify Candidate Actions
    results = engine.run_full_inspection()
    recs = results.get("recommendations", {}).get("recommendations", [])
    
    # Filter for recommendations that involve process termination
    optimizable = [r for r in recs if "terminating this process" in r['action'].lower() or "restarting this application" in r['action'].lower()]
    
    if not optimizable:
        print("[+] System is currently optimal. No safe automated actions required.")
        return

    print(f"=== FOUND {len(optimizable)} OPTIMIZABLE TARGET(S) ===")
    
    # 2. Safety Validation & User Confirmation Loop
    for r in optimizable:
        target_str = r['target']
        match = re.search(r"PID:(\d+)\s*\((.*?)\)", target_str)
        
        if match:
            pid = int(match.group(1))
            name = match.group(2)
            
            print(f"\n[TARGET] {name} (PID: {pid})")
            print(f"  -> Reason: Flagged as a {r['priority']} level resource concern.")
            
            if optimizer.is_safe_to_terminate(pid, name):
                choice = input(f"  -> Terminate this process to free resources? [y/N]: ")
                if choice.strip().lower() == 'y':
                    res = optimizer.terminate_process(pid, name)
                    if res["status"] == "success":
                        print(f"  [+] {res['message']}")
                    else:
                        print(f"  [-] Failed: {res['message']}")
                else:
                    print("  [*] Action skipped by user.")
            else:
                print("  [-] Action blocked by CAPX Safety Engine (Critical System Process).")
                
    print("\n[*] Optimization complete.")


def handle_web(args: argparse.Namespace) -> None:
    """Launches the local Flask web dashboard."""
    logger.info("Launching CAPX Web UI...")
    print("[*] Starting CAPX local web server on http://127.0.0.1:5000")
    print("[*] Press CTRL+C to quit.")
    
    from capx.app import create_app
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="capx",
        description="CAPX - Cyber Analysis & Protection eXplorer"
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Inspect Command
    inspect_parser = subparsers.add_parser("inspect", help="Run full system and security analysis")
    inspect_parser.add_argument("--export", action="store_true", help="Export findings to a JSON report")

    # Monitor Command
    monitor_parser = subparsers.add_parser("monitor", help="Continuously monitor system health and security")
    
    # Optimize Command
    optimize_parser = subparsers.add_parser("optimize", help="Guided performance optimization and cleanup")
    
    # Web Command
    web_parser = subparsers.add_parser("web", help="Launch the local Flask web dashboard")
    
    args = parser.parse_args()

    if args.command == "inspect":
        handle_inspect(args)
    elif args.command == "monitor":
        handle_monitor(args)
    elif args.command == "optimize":
        handle_optimize(args)
    elif args.command == "web":
        handle_web(args)
    elif args.command is None:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()