# PQC-SOC Readiness Scanner
# This is where everything starts. 
# The scanner connects to a target, grabs its TLS certificate, checks what cryptographic algorithms it's using, and flags anything that won't survive a quantum computer.
# Built on the HNDL threat model, the attack is already happening.
# Author: Surendra Babu

import socket
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Pull in the detection functions from the certificate analyser module
from modules.certificate_analyser import get_certificate, analyse_certificate, scan_from_file

# Single console instance used throughout for all formatted output.
console = Console()



# Takes the findings from above and displays them in a clean color coded table.
def display_results(target, findings):

    # Build the header banner so we know which target was just scanned.
    console.print(Panel(f"PQC-SOC Readiness Scanner - Target: {target}", style="bold blue"))

    # Create an empty table
    results_table = Table(show_header=True, header_style="bold white")

    # Add the columns
    results_table.add_column("Target", style="cyan")
    results_table.add_column("Algorithm")
    results_table.add_column("Key Size")
    results_table.add_column("Vulnerable")
    results_table.add_column("Issuer")
    results_table.add_column("Expires")

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
        style=row_color
    ) 

    # Print the finished table to the terminal
    console.print(results_table)

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

    # Read what the user typed in the command line and store it
    arguments = parser.parse_args()

    # --- Single target mode ---
    if arguments.target:

        # Try to run the full scan - if anything goes wrong, the except blocks below handle it.
        try:

            # Step 1: Connect to the target and grab its certificate.
            console.print(f"\n[bold cyan]Connecting to {arguments.target} on port {arguments.port}...[/bold cyan]")
            certificate = get_certificate(arguments.target, arguments.port)

            # Step 2: Look inside the certificate and analyse what was found.
            console.print("[bold cyan]Analysing certificate...[/bold cyan]")
            findings = analyse_certificate(certificate)

            # Step 3: Display everything in a clean table.
            display_results(arguments.target, findings)

        # Target domain  doesn't exist, or can't be found.
        except socket.gaierror:
            console.print(f"\n[bold red]Error: Could not find '{arguments.target}'. Check the domain and try again.[/bold red]")

        # Server took too long to respond
        except TimeoutError:
            console.print(f"\n[bold red]Error: Connection to '{arguments.target}' timed out. Server may be down.[/bold red]")

        # Anything else that goes wrong
        except Exception as error:
            console.print(f"\n[bold red]Something went wrong: {error}[/bold red]")

    # --- File of targets mode ---
    elif arguments.targets:
        scan_from_file(arguments.targets, arguments.port, display_results, console)
        