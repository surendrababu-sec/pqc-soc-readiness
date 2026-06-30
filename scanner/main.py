# PQC-SOC Readiness Scanner
# This is where everything starts. 
# The scanner connects to a target, grabs its TLS certificate, checks what cryptographic algorithms it's using, and flags anything that won't survive a quantum computer.
# Built on the HNDL and quantum authentication forgery threat models.
# Author: Surendra Babu Chilakaluru

import socket
import argparse
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from modules.certificate_analyser import get_certificate, analyse_certificate, scan_from_file
from modules.risk_engine import evaluate_risk
from modules.pcap_analyser import analyse_pcap
from modules.cef_writer import save_cef_report, sort_findings_by_priority

# Single console instance used throughout for all formatted output.
console = Console()



# Takes the findings from above and displays them in a clean color coded table.
def display_results(target, findings, risk):

    # Build the header banner so we know which target was just scanned.
    console.print(Panel(f"PQC-SOC Readiness Scanner - Target: {target}", style="bold blue"))

    # Create an empty table
    results_table = Table(show_header=True, header_style="bold white", expand=True)

    # Add the columns
    results_table.add_column("Target", style="cyan")
    results_table.add_column("Algorithm")
    results_table.add_column("Key Size")
    results_table.add_column("Vulnerable")
    results_table.add_column("Issuer")
    results_table.add_column("Expires")
    results_table.add_column("Quantum Exposure Score")
    results_table.add_column("Severity")
    results_table.add_column("NIST Standard")

    # Decide the risk label and row colour based on what was found
    if findings["vulnerable"]:
        risk_label = "YES - Quantum Vulnerable"
        row_color = "red"
    elif findings["vulnerable"] is None:
        risk_label = "UNKNOWN - Further Analysis Needed"
        row_color = "yellow"
    else:
        risk_label = "NOT DETECTED"
        row_color = "green"
    
    # Add one row with everything we found about the target.
    results_table.add_row(
        target,
        findings["algorithm"],
        f"{findings['key_size']} bits" if findings['key_size'] else "N/A",
        risk_label,
        findings["issuer"],
        findings["expires"],
        str(risk.score),
        risk.severity,
        risk.nist_standard,
        style=row_color
    ) 

    # Print the finished table to the terminal
    console.print(results_table)

    # Print the migration advice
    console.print(Panel(risk.migration_advice, title="Migration Advice", style="yellow"))

    # Print the rationale
    console.print(Panel(risk.rationale, title="Rationale", style="cyan"))

# Shows PCAP findings in a colour coded table.
# This is separate from display_results because PCAP findings carry different fields
def display_pcap_results(all_findings, all_risks):

    console.print(Panel("PQC-SOC Readiness Scanner - PCAP Handshake Analysis", style="bold blue"))

    results_table = Table(show_header=True, header_style="bold white", expand=True)

    results_table.add_column("Server Endpoint", style="cyan")
    results_table.add_column("Client IP")
    results_table.add_column("Algorithm")
    results_table.add_column("Cipher Suite")
    results_table.add_column("Quantum Exposure Score")
    results_table.add_column("Severity")
    results_table.add_column("NIST Standard")
    results_table.add_column("Server Hello")

    for finding, risk in zip(all_findings, all_risks):

        # Red for vulnerable, green for safe, yellow for unsure ones
        if finding["vulnerable"] is True:
            row_color = "red"
        elif finding["vulnerable"] is False:
            row_color = "green"
        else:
            row_color = "yellow"

        # Without the Server Hello, only the client's offered options are known
        # not what the server chose.
        server_hello_label = "Yes" if finding.get("has_server_hello") else "No, client offer only"

        results_table.add_row(
            finding["target"],
            finding["client_ip"],
            finding["algorithm"],
            finding["cipher_suite"],
            str(risk.score),
            risk.severity,
            risk.nist_standard,
            server_hello_label,
            style=row_color
        )

    console.print(results_table)

    # Print migration advice only for sessions that are vulnerable
    printed_advice = set()  # Is to avoid duplicate advices
    for finding, risk in zip(all_findings, all_risks):
        if finding["vulnerable"] is True and finding["algorithm"] not in printed_advice:
            console.print(Panel(risk.migration_advice, title=f"Migration Advice - {finding['algorithm']}", style="yellow"))
            printed_advice.add(finding["algorithm"])

# Takes everything the scanner found and writes it into a structured JSON file.
# SIEM tools like Splunk and QRadar can automatically pick this up and process the findings without any manual effort from the analyst.
def save_json_report(filename, all_findings, arguments,  total_in_file=None, failed_details=None):

    # If nothing came in for failed_details, start a fresh empty list
    failed_details = failed_details or []

    # Always use the .json extension for clarity, even if the user forgets to add it.
    # No two scan reports will overwrite each other 
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{Path(filename).stem}_{timestamp}.json"


    # Output path
    output_folder = Path(__file__).parent/"output"
    output_folder.mkdir(exist_ok=True) # Create the output folder if it doesn't exist.
    full_output_path = output_folder/filename

    # Build the metadata section
    scan_metadata = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": "0.1",
        "threat_model": "HNDL (Harvest Now, Decrypt Later) and quantum authentication forgery",
        "context_settings": {
            "data_sensitivity": arguments.sensitivity,
            "data_lifetime": arguments.lifetime,
            "exposure_surface": arguments.exposure
        },
        "total_in_file": total_in_file if total_in_file else len(all_findings),
        "successfully_scanned": len(all_findings),
        "vulnerable_count": sum(1 for finding in all_findings if finding["vulnerable"]),
        "hybrid_pqc_count": sum(1 for finding in all_findings if finding["vulnerable"] is False and "ECC+ML-KEM" in finding["algorithm"]),
        "post_quantum_safe_count": sum(1 for finding in all_findings if finding["vulnerable"] is False and "ECC+ML-KEM" not in finding["algorithm"]),
        "failed_count": len(failed_details)
    }

    # Bundle the metadata, findings (urgency-first order), and failure details together into one complete report
    scan_report = {
        "scan_metadata": scan_metadata,
        "findings": sort_findings_by_priority(all_findings),
        "failed_scans": failed_details
    }

    # Write the report to the specified file
    with open(full_output_path, "w") as output_file:
        json.dump(scan_report, output_file, indent=2)

    console.print(f"\n[bold green]JSON report saved to '{full_output_path}'[/bold green]")
                                             


# This is the main runner
# Takes the target and optional port directly from the command line, runs the scan, and shows the results.
if __name__ == "__main__":

    # Set up the command line interface
    parser = argparse.ArgumentParser(
        description=(
        "PQC-SOC Readiness Scanner\n"
        "─────────────────────────────────────────────────────────────\n"
        "Audits TLS for quantum-vulnerable cryptography\n"
        "(RSA, ECC, DSA, DH, EdDSA) under two distinct quantum threats:\n"
        "HNDL (confidentiality) and authentication forgery (certificates).\n\n"
        "Identifies and scores systems requiring migration to NIST PQC standards:\n"
        "  FIPS 203 (ML-KEM)  - key encapsulation\n"
        "  FIPS 204 (ML-DSA)  - digital signatures\n"
        "  FIPS 205 (SLH-DSA) - hash-based signatures\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # The user must provide either a single target or a file of targets - not both
    scan_group = parser.add_mutually_exclusive_group(required=True)

    # Single target - one domain typed directly
    scan_group.add_argument("target", nargs="?", help="Single target domain to scan (e.g. google.com)")

    # File of targets - path to a text file with one domain per line
    scan_group.add_argument("--targets", metavar="file", help="Path to a text file containing target domains (one per line)")

    # PCAP file - path to a network capture file for handshake analysis
    scan_group.add_argument("--pcap", metavar="file", help="Path to a PCAP capture file for TLS handshake analysis (e.g. capture.pcap)")

    # Port is optional - if not specified, it defaults to 443 (standard HTTPS)
    parser.add_argument("--port", type=int, default=443, metavar="port", help="Target port (default: 443)")

    # How sensitive is the data this target is protecting?
    parser.add_argument("--sensitivity", type=int, default=2, choices=[1,2,3], metavar="level", help="Data sensitivity level - 1=low, 2=medium, 3=high (default: 2)")

    # How long does this data need tostay secret?
    parser.add_argument("--lifetime", type=int, default=2, choices=[1,2,3], metavar="level", help="Data lifetime - 1=months, 2=years, 3=decades (default: 2)")

    # How exposed is this endpoint to the outside world?
    parser.add_argument("--exposure", type=int, default=2, choices=[1,2,3], metavar="level", help="Exposure surface - 1=internal only, 2=partner-facing, 3=public internet (default: 2)")

    # Where to save the JSON report - optional, only saves if this flag is provided
    parser.add_argument("--output", metavar="file", help="Save the scan results to a JSON file for SIEM integration (e.g. report.json)")

    # Where to save the CEF report - optional, only saves if this flag is provided
    parser.add_argument("--cef-output", metavar="file", help="Save the scan results to a CEF file for SIEM integration (e.g. report.cef)")

    # Read what the user typed in the command line and store it
    arguments = parser.parse_args()

    # --- Single target mode ---
    if arguments.target:

        all_findings = []  

        # Try to run the full scan - if anything goes wrong, the except blocks below handle it.
        try:

            # Step 1: Connect to the target and grab its certificate.
            console.print(f"\n[bold cyan]Connecting to {arguments.target} on port {arguments.port}...[/bold cyan]")
            certificate = get_certificate(arguments.target, arguments.port)

            # Step 2: Look inside the certificate and analyse what was found.
            console.print("[bold cyan]Analysing certificate...[/bold cyan]")
            findings = analyse_certificate(certificate)

            # Step 3: Run the risk engine to score and get NIST recommendations.
            console.print("[bold cyan]Evaluating risk...[/bold cyan]")
            risk = evaluate_risk(findings["algorithm"], findings["key_size"], data_sensitivity=arguments.sensitivity, data_lifetime=arguments.lifetime, exposure_surface=arguments.exposure)

            # Step 4: Display everything in a clean table.
            display_results(arguments.target, findings, risk)

            # Step 5: Collect the finding for the JSON report.
            all_findings.append({
                "target": arguments.target,
                "algorithm": findings["algorithm"],
                "key_size": findings["key_size"],
                "vulnerable": findings["vulnerable"],
                "issuer": findings["issuer"],
                "expires": findings["expires"],
                "quantum_exposure_score": risk.score,
                "threat_category": risk.threat_category,
                "severity": risk.severity,
                "nist_standard": risk.nist_standard,
                "migration_advice": risk.migration_advice,
                "rationale": risk.rationale
            })

        # Target domain  doesn't exist, or can't be found.
        except socket.gaierror:
            console.print(f"\n[bold red]Error: Could not find '{arguments.target}'. Check the domain and try again.[/bold red]")

        # Server took too long to respond
        except TimeoutError:
            console.print(f"\n[bold red]Error: Connection to '{arguments.target}' timed out. Server may be down.[/bold red]")

        # Anything else that goes wrong
        except Exception as error:
            console.print(f"\n[bold red]Something went wrong: {error}[/bold red]")

        # Save the JSON report if the --output was specified.
        if arguments.output and all_findings:
            save_json_report(arguments.output, all_findings, arguments)

        # CEF is a separate, optional output. Saved independently of JSON
        if arguments.cef_output and all_findings:
            saved_path = save_cef_report(arguments.cef_output, all_findings)
            console.print(f"\n[bold green]CEF report saved to '{saved_path}'[/bold green]")

    # --- File of targets mode ---
    elif arguments.targets:
        all_findings, total_in_file, failed_details = scan_from_file(arguments.targets, arguments.port, display_results, console, arguments.sensitivity, arguments.lifetime, arguments.exposure)

        if arguments.output and all_findings:
            save_json_report(arguments.output, all_findings, arguments, total_in_file=total_in_file, failed_details=failed_details)

        if arguments.cef_output and all_findings:
            saved_path = save_cef_report(arguments.cef_output, all_findings)
            console.print(f"\n[bold green]CEF report saved to '{saved_path}'[/bold green]")

    # --- PCAP handshake analysis mode ---
    elif arguments.pcap:

        console.print(f"\n[bold cyan]Loading PCAP file: {arguments.pcap}...[/bold cyan]")

        try:

            # Hand the file to the PCAP analyser and get back a list of findings
            pcap_findings = analyse_pcap(arguments.pcap)

            if not pcap_findings:
                # Nothing found, let the user know clearly
                console.print("\n[bold yellow]No TLS handshakes found in this capture file.[/bold yellow]")
                console.print("[yellow]Make sure the file contains TLS traffic and try again.[/yellow]")

            else:
                console.print("[bold cyan]Evaluating quantum exposure for each session...[/bold cyan]")

                # Score each finding through the risk engine.
                # These came from handshakes not certificates, so key_exchange is the right usage.
                all_risks = []
                for finding in pcap_findings:
                    risk = evaluate_risk(
                        finding["algorithm"],
                        finding["key_size"],
                        data_sensitivity=arguments.sensitivity,
                        data_lifetime=arguments.lifetime,
                        exposure_surface=arguments.exposure,
                        usage="key_exchange",
                        key_size_source = finding["key_size_source"]
                    )
                    all_risks.append(risk)

                # Show the results table with migration advice panels underneath
                display_pcap_results(pcap_findings, all_risks)

                # Print a summary at the bottom
                total_sessions = len(pcap_findings)
                vulnerable_count = sum(1 for f in pcap_findings if f["vulnerable"] is True)
                hybrid_count = sum(1 for f in pcap_findings if f["vulnerable"] is False and "ECC+ML-KEM" in f["algorithm"])
                post_quantum_safe_count = sum(1 for f in pcap_findings if f["vulnerable"] is False and "ECC+ML-KEM" not in f["algorithm"])
                unknown_count = sum(1 for f in pcap_findings if f["vulnerable"] is None)

                console.print(f"\n[bold]Scan complete.[/bold]")
                console.print(f"Sessions analysed  : {total_sessions}")
                console.print(f"[bold red]Vulnerable         : {vulnerable_count}[/bold red]")
                console.print(f"[cyan]Hybrid PQC         : {hybrid_count}[/cyan]")
                console.print(f"[bold green]Post-quantum safe  : {post_quantum_safe_count}[/bold green]")
                console.print(f"[bold yellow]Unknown            : {unknown_count}[/bold yellow]")

                # JSON and CEF both need the scores attached to each finding first,
                # so this step runs if either one was asked for
                if arguments.output or arguments.cef_output:
                    enriched_findings = []
                    for finding, risk in zip(pcap_findings, all_risks):
                        # Copy the finding dictionary
                        enriched = dict(finding)
                        enriched["quantum_exposure_score"] = risk.score
                        enriched["threat_category"]        = risk.threat_category
                        enriched["severity"]               = risk.severity
                        enriched["nist_standard"]          = risk.nist_standard
                        enriched["migration_advice"]       = risk.migration_advice
                        enriched["rationale"]              = risk.rationale
                        enriched_findings.append(enriched)
                    
                    # JSON and CEF are independent - either, both, or neither can be requested
                    if arguments.output:
                        save_json_report(arguments.output, enriched_findings, arguments, total_in_file=total_sessions)

                    if arguments.cef_output:
                        saved_path = save_cef_report(arguments.cef_output, enriched_findings)
                        console.print(f"\n[bold green]CEF report saved to '{saved_path}'[/bold green]")
        
        except FileNotFoundError as error:
            console.print(f"\n[bold red]{error}[/bold red]")

        except ValueError as error:
            console.print(f"\n[bold red]{error}[/bold red]")

        except Exception as error:
            console.print(f"\n[bold red]Something went wrong during PCAP analysis: {error}[/bold red]")


                    