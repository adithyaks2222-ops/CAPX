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
    
    sys_facts = results.get("system_facts", {})
    if sys_facts.get("status") == "success":
        print("=== SYSTEM HEALTH ===")
        print(f"OS: {sys_facts['os']['system']} {sys_facts['os']['release']}")
        print(f"CPU Usage: {sys_facts['cpu']['usage_percent']}%")
        print(f"Memory Usage: {sys_facts['memory']['usage_percent']}%\n")
        
    proc_findings = results.get("process_findings", {})
    if proc_findings.get("status") == "success":
        print(f"=== PROCESS ANALYSIS ({proc_findings['analyzed_count']} processes analyzed) ===")
        findings = proc_findings.get("findings", [])
        if not findings:
            print("[+] No process anomalies detected.")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['type']} | {f['source']} -> {f['details']}")
    print("\n[*] Inspection Complete.")

    # ... (Keep existing system and process printouts here) ...

    net_findings = results.get("network_findings", {})
    if net_findings.get("status") == "success":
        print(f"\n=== NETWORK ANALYSIS ({net_findings['analyzed_count']} connections analyzed) ===")
        findings = net_findings.get("findings", [])
        if not findings:
            print("[+] No anomalous network exposure detected.")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['type']} | {f['source']} -> {f['details']}")

    print("\n[*] Inspection Complete.")

    # ... (Keep existing system, process, and network printouts) ...

    startup_findings = results.get("startup_findings", {})
    if startup_findings.get("status") == "success":
        print(f"\n=== STARTUP & PERSISTENCE ({startup_findings['analyzed_count']} items analyzed) ===")
        findings = startup_findings.get("findings", [])
        if not findings:
            print("[+] No suspicious startup anomalies detected.")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['type']} | {f['source']} -> {f['details']}")

    print("\n[*] Inspection Complete.")


    # ... (Keep existing system, process, network, and startup printouts) ...

    # NEW: Detection Engine Alerts
    detection = results.get("detection_alerts", {})
    if detection.get("status") == "success":
        print(f"\n=== DETECTION ENGINE ({detection['alerts_count']} correlated alerts) ===")
        alerts = detection.get("alerts", [])
        if not alerts:
            print("[+] No correlated behavioral anomalies detected.")
        else:
            for a in alerts:
                print(f"[{a['severity']}] {a['type']} | {a['source']} -> {a['details']}")

    print("\n[*] Inspection Complete.")

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
    inspect_parser = subparsers.add_parser(
        "inspect", help="Run full system and security analysis"
    )
    
    args = parser.parse_args()

    if args.command == "inspect":
        handle_inspect(args)
    elif args.command is None:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()