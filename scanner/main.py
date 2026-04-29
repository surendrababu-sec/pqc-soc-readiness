# PQC-SOC Readiness Scanner
# This is where everything starts. 
# The scanner connects to a target, grabs its TLS certificate, checks what cryptographic algorithms it's using, and flags anything that won't survive a quantum computer.
# Built on the HNDL threat model, the attack is already happening.
# Author: Surendra Babu

import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Single console instance used throughout for all formatted output.
console = Console()

# Reaches out to the target server, completes the TLS handshake and pulls back the certificate.
def get_certificate(target):

    # Set up secure connection settings - turning off certificate verification on purpose.
    # This is a scanner, not a browser. It needs to inspect even the broken, expired, and self-signed certificates - those are often the most interesting ones from a security perspective.
    tls_settings = ssl.create_default_context()
    tls_settings.check_hostname = False
    tls_settings.verify_mode = ssl.CERT_NONE

    # Open a basic network connection to the target on port 443 (HTTPS)
    # If the server doesn't respond in 10 sec, give up
    with socket.create_connection((target, 443), timeout=10) as connection:

        # Upgrade the basic connection to a secure TLS connection.
        # This is where the handshake happens and the certificate appears.
        with tls_settings.wrap_socket(connection, server_hostname=target) as secure_connection:

            # Grab the raw certificate from the server
            raw_certificate = secure_connection.getpeercert(binary_form=True)

    # Converts the raw certificate into a readable format.
    certificate = x509.load_der_x509_certificate(raw_certificate)

    return certificate

# Looks inside the certificate and figures out what algorithm is being used.
# How big the key is, and whether it will survive a quantum computer.
def analyse_certificate(certificate):
    
    # Pull the public key out of the certificate.
    key = certificate.public_key()

    # Start building our findings
    findings = { "algorithm": None, "key_size": None, "vulnerable": None, "issuer": None, "expires": None}

    # Check if the key is RSA or ECC, which are broken by Shor's algorithm on a quantum computer.
    if isinstance(key, rsa.RSAPublicKey):
        findings["algorithm"] = "RSA"
        findings["key_size"] = key.key_size
        findings["vulnerable"] = True

    elif isinstance(key, ec.EllipticCurvePublicKey):
        findings["algorithm"] = f"ECC ({key.curve.name})"
        findings["key_size"] = key.key_size
        findings["vulnerable"] = True

    # DSA and DH rarely appear in TLS certificates, included here for completeness
    elif isinstance(key, dsa.DSAPublicKey):
        findings["algorithm"] = "DSA"
        findings["key_size"] = key.key_size
        findings["vulnerable"] = True

    elif isinstance(key, dh.DHPublicKey):
        findings["algorithm"] = "DH"
        findings["key_size"] = key.key_size
        findings["vulnerable"] = True

    # If it's neither of the above algorithms, we don't know what it is yet
    else:
        findings["algorithm"] = "Unknown- further analysis needed"
        findings["key_size"] = None
        findings["vulnerable"] = None

    # Grab who issued this certificate, and when it expires
    findings["issuer"] = certificate.issuer.rfc4514_string()
    findings["expires"] = certificate.not_valid_after_utc.strftime("%d %b %Y")

    return findings

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

    # Decide the risk label and row colour based on what we found
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
# Takes the target from the user, runs the scan, and shows the results.
if __name__ == "__main__":

    # Ask the user which domain they want to scan.
    target = input("Enter target domain to scan (e.g. example.com): ")

    try:

        # Step 1: Connect to the target and grab its certificate.
        console.print(f"\n[bold cyan]Connecting to {target}...[/bold cyan]")
        certificate = get_certificate(target)

        # Step 2: Look inside the certificate and analyse what we found.
        console.print(f"[bold cyan]Analysing certificate...[/bold cyan]")
        findings = analyse_certificate(certificate)

        # Step 3: Display everything in a clean table.
        display_results(target, findings)

    # Target domain  doesn't exist, or can't be found.
    except socket.gaierror:
        console.print(f"\n[bold red]Error: Could not find '{target}'. Check the domain and try again.[/bold red]")

    # Server took too long to respond
    except TimeoutError:
        console.print(f"\n[bold red]Error: Connection to '{target}' timed out. Server may be down.[/bold red]")

    # Anything else that goes wrong
    except Exception as error:
        console.print(f"\n[bold red]Something went wrong: {error}[/bold red]")
        