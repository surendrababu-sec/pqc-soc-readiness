# PQC-SOC Readiness Scanner
# This is where everything starts. 
# The scanner connects to a target, grabs its TLS certificate, checks what cryptographic algorithms it's using, and flags anything that won't survive a quantum computer.
# Built on the HNDL threat model, the attack is already happening.
# Author: Surendra Babu

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
    results_table.add_column("HNDL Score")
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

# Takes everything the scanner found and writes it into a structured JSON file.
# SIEM tools like Splunk and QRadar can automatically pick this up and process the findings without any manual effort from the analyst.
def save_json_report(filename, all_findings, arguments,  total_in_file=None, failed_count=0):

    # Always use the .json extension for clarity, even if the user forgets to add it.
    # No two scan reports will overwrite each other 
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{Path(filename).stem}_{timestamp}.json"


    # Output path
    output_folder = Path(__file__).parent/"output"
    output_folder.mkdir(exist_ok=True) # Create the outputfoler if it doesn't exist.
    full_output_path = output_folder/filename

    # Build the metadata section
    scan_metadata = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": "0.1",
        "threat_model": "HNDL - Harvest Now, Decrypt Later",
        "context_settings": {
            "data_sensitivity": arguments.sensitivity,
            "data_lifetime": arguments.lifetime,
            "exposure_surface": arguments.exposure
        },
        "total_in_file": total_in_file if total_in_file else len(all_findings),
        "successfully_scanned": len(all_findings),
        "vulnerable_count": sum(1 for finding in all_findings if finding["vulnerable"]),
        "failed_count": failed_count
    }

    # Bundle the metadata and findings together into one complete report
    scan_report = {
        "scan_metadata": scan_metadata,
        "findings": all_findings
    }

    # Write the report to the specified file
    with open(full_output_path, "w") as output_file:
        json.dump(scan_report, output_file, indent=2)

    console.print(f"\n[bold green]Report saved to '{full_output_path}'[/bold green]")
                                             


# This is the main runner
# Takes the target and optional port directly from the command line, runs the scan, and shows the results.
if __name__ == "__main__":

    # Set up the command line interface
    parser = argparse.ArgumentParser(
        description=(
            "PQC-SOC Readiness Scanner\n"
        "─────────────────────────────────────────────────────────────\n"
        "Audits TLS certificates for quantum-vulnerable cryptography\n"
        "(RSA, ECC, DSA, DH) under the Harvest Now, Decrypt Later\n"
        "(HNDL) threat model.\n\n"
        "Identifies systems requiring migration to NIST PQC standards:\n"
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

    # Port is optional - if not specified, it defaults to 443 (standard HTTPS)
    parser.add_argument("--port", type=int, default=443, metavar="port", help="Target port (default: 443)")

    # How sensitive is the data this target is protecting?
    parser.add_argument("--sensitivity", type=int, default=2, choices=[1,2,3], metavar="level", help="Data sensitivity level - 1=low, 2=medium, 3=high (default: 2)")

    # How long does this data need tostay secret?
    parser.add_argument("--lifetime", type=int, default=2, choices=[1,2,3], metavar="level", help="Data lifetime - 1=months, 2=years, 3=decades (default: 2)")

    # How exposed is this endpoint to the outside world?
    parser.add_argument("--exposure", type=int, default=2, choices=[1,2,3], metavar="level", help="Exposure surface - 1=internal only, 2=partner-facing, 3=public internet (default: 2)")

    # Where to save the JSON report -optional, only saves if this flag is provided
    parser.add_argument("--output", metavar="file", help="Save the scan results to a JSON file for SIEM integration (e.g. report.json)")

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
                "hndl_score": risk.score,
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

    # --- File of targets mode ---
    elif arguments.targets:
        all_findings, total_in_file, failed_count = scan_from_file(arguments.targets, arguments.port, display_results, console, arguments.sensitivity, arguments.lifetime, arguments.exposure)

        if arguments.output and all_findings:
            save_json_report(arguments.output, all_findings, arguments, total_in_file=total_in_file, failed_count=failed_count)


        