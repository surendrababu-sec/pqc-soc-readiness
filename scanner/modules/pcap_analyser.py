import struct 
import csv
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pathlib import Path
from scapy.all import rdpcap, IP, TCP

# Path to knowledge folder
knowledge_folder = Path(__file__).parent.parent/ "knowledge"

# Loads the IANA cipher suite registry from our local CSV file.
# Builds a flat lookup dictionary so classify_cipher_suite can find any suite instantly.
def load_cipher_suites():
    
    # This is the empty dictionary to be fill and return
    # Key = the integer cipher suite value
    # Value = suite name, key exchange, and vulnerability
    cipher_suite_lookup = {}

    csv_file_path = knowledge_folder/ "cipher_suites.csv"

    with open(csv_file_path, "r", encoding="utf-8") as open_file:

        csv_reader = csv.reader(open_file)

        # Skip the header row
        next(csv_reader)

        for row in csv_reader:

            # Skip rows that do not have enough columns
            if len(row) < 2:
                continue

            # Remove the quote characters & spaces
            raw_value = row[0].strip('"').strip()

            # Skip range and wildcard entries, these represent blocks, not individual suites
            if "-" in raw_value or "*" in raw_value:
                continue

            # Read the description
            suite_name = row[1].strip()

            # Skip reserved and unassigned entries
            if not suite_name or "reserved" in suite_name.lower() or "unassigned" in suite_name.lower():
                continue

            # Split the two hex bytes apart on the comma
            value_parts = raw_value.split(",")

            # Need exactly two parts, skip anything malformed
            if len(value_parts) != 2:
                continue

            # Convert each hex string to an integer
            try:
                high_byte = int(value_parts[0], 16)
                low_byte  = int(value_parts[1], 16)
            except ValueError:
                # If conversion fails
                continue

            # Combine the two bytes into one 2-byte integer
            # Two bytes arrive separately, so move the high byte one full byte to the left
            # and put the low byte into the space that opens up. Together make one value.
            full_value = (high_byte << 8) | low_byte

            # Work out the key exchange algorithm from the name
            # The order matters
            if "ECDHE" in suite_name or "ECDH_" in suite_name:
                key_exchange = "ECC"
                is_vulnerable = True

            elif "DHE" in suite_name or "_DH_" in suite_name:
                key_exchange = "DH"
                is_vulnerable = True

            elif "TLS_AES" in suite_name or "TLS_CHACHA20" in suite_name:
                key_exchange = "TLS13"
                is_vulnerable = None    # depends on supported groups

            elif "RSA" in suite_name:
                key_exchange = "RSA"
                is_vulnerable = True

            else:
                # Kerberos, PSK, SRP, GOST, NULL - not relevant to HNDL
                key_exchange   = "Unknown"
                is_vulnerable  = None

            # Store the cipher suite in the lookup dictionary
            cipher_suite_lookup[full_value] = {"name":suite_name, "key_exchange":key_exchange, "quantum_vulnerable":is_vulnerable}

    return cipher_suite_lookup

# Load the cipher suites once when this module is imported.
ALL_CIPHER_SUITES = load_cipher_suites()

# Loads the IANA supported groups registry from our local CSV file.
# Same idea as load_cipher_suites
def load_supported_groups():

    # The dictionary will fill and return
    # Key = group ID as a plain integer
    # Value = group name, its type, and whether it is quantum vulnerable
    supported_group_lookup = {}

    csv_file_path  = knowledge_folder/"supported_groups.csv"

    with open(csv_file_path, "r", encoding="utf-8") as open_file:

        csv_reader = csv.reader(open_file)

        # Skip the header row
        next(csv_reader)

        for row in csv_reader:

            # Skips rows that do not have enough columns
            if len(row) < 2:
                continue

            raw_value = row[0].strip()

            # Skip range rows and wildcard rows
            if "-" in raw_value or "*" in raw_value:
                continue

            group_name = row[1].strip()

            # Skip reserved and unassigned entries
            if not group_name or "reserved" in group_name.lower() or "unassigned" in group_name.lower():
                continue

            try:
                group_id = int(raw_value)
            except ValueError:
                # If it is not a clean number, skip the row
                continue

            # Work out the group type from the description.
            # The order matters
            if "MLKEM" in group_name and any(classical in group_name for classical in ["X25519", "SecP", "secp", "SM2"]):
                # Classical curve combined with ML-KEM - hybrid, transitional
                group_type = "ECC+ML-KEM"
                is_vulnerable = False

            elif "Kyber" in group_name:
                # Old draft hybrid - obsolete
                group_type = "ECC+ML-KEM (obsolete)"
                is_vulnerable = False

            elif "MLKEM" in group_name:
                # Pure ML-KEM
                group_type = "ML-KEM"
                is_vulnerable = False

            elif group_name.startswith("ffdhe"):
                # Finite field Diffle-Hellman - quantum vulnerable
                group_type = "DH"
                is_vulnerable = True

            elif any(classical in group_name for classical in ["secp", "sect", "x25519", "x448", "brainpool", "GC256", "GC512", "curveSM2", "arbitrary"]):
                # Classical elliptic curve - quantum vulnerable
                group_type = "ECC"
                is_vulnerable = True

            else:
                group_type = "Unknown"
                is_vulnerable = None

            supported_group_lookup[group_id] = {"name": group_name, "group_type": group_type, "quantum_vulnerable": is_vulnerable}
    
    return supported_group_lookup

# Load once when this module is imported
ALL_SUPPORTED_GROUPS = load_supported_groups()

# Peeks inside a raw TCP payload and checks whether it carries a TLS Certificate message.
# If it does, pulls out the raw DER bytes of the first certificate in the chain.
def extract_certificate_der_from_packet(raw_payload):

    # Need at least 9bytes- outer body (5) + handshake header (4)
    if len(raw_payload) < 9:
        return None
    
    # Not a TLS handshake record
    if raw_payload[0] != 0x16:
        return None
    
    # Not a TLS version
    if raw_payload[1] != 0x03:
        return None
    
    record_length = struct.unpack(">H", raw_payload[3:5])[0]

    if len(raw_payload) < 5 + record_length:
        return None
    
    # Slice out just the handshake data
    record_data = raw_payload[5:5+record_length]

    # Not a certificate message
    if record_data[0] != 0x0B:
        return None 
    
    # Check enough bytes for the certificate list length
    if len(record_data) < 10:
        return None
    
    # Bytes 7-9 of the record_data gives the first cert len
    first_cert_length = struct.unpack(">I", b'\x00' + record_data[7:10])[0]

    if len(record_data) < 10 + first_cert_length:
        return None
    
    # Slice out the raw DER bytes
    der_bytes =  record_data[10:10+first_cert_length]

    #  A certificate shorter than 64 bytes is almost certainly malformed
    if len(der_bytes) < 64:
        return None
    
    return der_bytes

# Takes raw DER certificate bytes and reads the public key size out of it.
def get_key_size_from_der(der_bytes):

    try:
        # Parse the raw bytes into a proper certificate object
        certificate = x509.load_der_x509_certificate(der_bytes)

        # Pull the public key out of the certificate
        public_key = certificate.public_key()

        # Both RSA and ECC hand the key size directly - no calculation needed
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.key_size
        
        # Any other key type - DSA, EdDSA, DH - not scored by key size
        return None
    
    except Exception:
        return None
    
# Connects directly to a server and grabs its certificate to read the key size.
# Used when the PCAP capture did not include the Certificate message.
def fetch_key_size_live(server_ip, server_port):

    try:
        # Skips the hostname verification
        # PCAP sessions give IP addresses, not hostnames. so standard verification would fail even on a perfectly valid connection
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Open the connection with a short timeout so internal IPs fail fast rather than hanging for 30 seconds before giving up
        with socket.create_connection((server_ip, server_port), timeout=3) as raw_connection:
            with ssl_context.wrap_socket(raw_connection) as secure_connection:

                # Pull the certificate bytes directly from the live connection
                der_bytes = secure_connection.getpeercert(binary_form=True)

                # Hand the DER bytes to the same parser 
                return get_key_size_from_der(der_bytes)
            
    except Exception:
        # Server unreachable, connection refused, timeout
        return None

# Used as a fallback when the actual key size cannot be read from the capture or a live fetch.
# Values are based on Cloudflare Radar 2024 TLS deployment statistics.
def get_modal_key_size(algorithm):

    if "RSA" in algorithm:
        return 2048  # RSA-2048 is the modal key size in public TLS
    
    elif "ECC" in algorithm:
        return 256   # P-256 is the most common curve in public TLS
    
    # DH and everything else - key size does not affect the risk score
    return None


# Tries three ways to get the key size for a PCAP finding, most accurate first.
# Returns the key size and a label so the caller always knows which tier was used.
def get_key_size_with_fallback(der_bytes, algorithm, server_ip, server_port):

    # Tier 1 - certificate was captured inside the PCAP itself
    # This is the most accurate source - same session, same moment in time
    if der_bytes is not None:
        key_size = get_key_size_from_der(der_bytes)
        if key_size is not None:
            return key_size, "pcap_certificate"
        
    # Tier 2 - live certificate fetch from the server
    # Only worth trying for RSA and ECC - the risk engine scores DH urgency regardless of key size, so a live fetch adds nothing for DH.
    if "RSA" in algorithm or "ECC" in algorithm:
        key_size = fetch_key_size_live(server_ip, server_port)
        if key_size is not None:
            return key_size, "live_fetch"
        
    # Tier 3 - modal baseline from documented field-wide deployment statistics
    # Covers internal IPs, offline servers, and anything else that fell through
    modal_key_size = get_modal_key_size(algorithm)
    return modal_key_size, "modal_baseline"


# Takes one cipher suite integer, looks it up in the loaded dictionary
def classify_cipher_suite(suite_value):

    # Used .get(), to return None instead of crashing if the suite is not in the list
    suite_entry = ALL_CIPHER_SUITES.get(suite_value)

    # This covers private use ranges and any suites added after the CSV was downloaded
    if suite_entry is None:
        return "Unknown", None, f"Unknown suite (0x{suite_value:04X})"
    
    algorithm = suite_entry["key_exchange"]
    is_vulnerable = suite_entry["quantum_vulnerable"]
    suite_name = suite_entry["name"]

    return algorithm, is_vulnerable, suite_name


# Takes the list of group IDs from a Client Hello
def classify_supported_groups(group_ids):

    has_vulnerable = False
    has_hybrid = False
    has_pure_pqc = False
    has_vulnerable_ecc = False    # track ECC and DH separately
    has_vulnerable_dh  = False    # which one dominates at the end, not mid-loop
    for group_id in group_ids:

        # Look up this group id in the loaded dictionary
        group_entry = ALL_SUPPORTED_GROUPS.get(group_id)

        if group_entry is None:
            continue

        group_type = group_entry["group_type"]

        if group_type == "ML-KEM":
            # Pure post-quantum
            has_pure_pqc = True

        elif "ECC+ML-KEM" in group_type:
            # Hybrid - classical curver combined with ML-KEM
            has_hybrid = True

        elif group_type == "DH":
            # Classical ffdh - quantum vulnerable
            has_vulnerable = True
            has_vulnerable_dh = True

        elif group_type == "ECC":
            # Classical elliptic curve - quantum vulnerable
            has_vulnerable = True
            has_vulnerable_ecc = True

    # If both ECC and DH groups are present, TLS 1.3 picks ECC.
    if has_vulnerable_ecc:
        dominant_vulnerable_type = "ECC"
    elif has_vulnerable_dh:
        dominant_vulnerable_type = "DH"
    else:
        dominant_vulnerable_type = "ECC"    # safe default



    # Now work out the overall verdict
    # The order matters, most specific first.

    if has_vulnerable and has_hybrid:
        # Both classical and hybrid groups are present
        # the server might pick the classical one, so flag as vulnerable
        return dominant_vulnerable_type, True
    
    elif has_vulnerable and not has_hybrid and not has_pure_pqc:
        # Only classical groups - fully quantum vulnerable
        return dominant_vulnerable_type, True
    
    elif has_hybrid and not has_vulnerable:
        # Only hybrid PQC groups
        return "ECC+ML-KEM", False
    
    elif has_pure_pqc and not has_vulnerable and not has_hybrid:
        # Only pure ML-KEM groups
        return "ML-KEM", False
    
    elif has_pure_pqc and has_hybrid and not has_vulnerable:
        # Mix of pure PQC and hybrid
        return "ML-KEM", False
    
    else:
        return "Unknown", None


# This is the one function that main.py calls directly.
# It opens the PCAP file, walks through every packet looking for TLS handshakes,
# pieces together what cipher suites are being negotiated,
# and hands back a clean list of findings for the risk engine to score.
def analyse_pcap(pcap_filepath):

    # Turn the file path into a Path object and check things about it
    pcap_path = Path(pcap_filepath)

    # Before doing anything else, does the file actually exist?
    if not pcap_path.exists():
        raise FileNotFoundError(f"Cannot find the PCAP file: {pcap_filepath}")
    
    # Make sure it is a capture file and not something unrelated
    if pcap_path.suffix.lower() not in [".pcap", ".pcapng", ".cap"]:
        raise ValueError(f"This needs to be a .pcap, .pcapng, or .cap file: {pcap_filepath}")

    # Hand the file to scapy and get back every packet as a list
    all_packets = rdpcap(str(pcap_path))

    # This tracks TLS sessions, while going through the packets
    # Key = four values that together identify one unique TCP connection
    # Value = everything we know about that session so far
    tls_sessions = {}

    for packet in all_packets:

        # Skip anything that is not a proper IP and TCP packet.
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            continue

        # Pull the raw bytes out of the TCP packet
        try:
            raw_payload = bytes(packet[TCP].payload)
        except Exception:
            continue

        if not raw_payload:
            continue

        # Is this a TLS handshake?
        is_handshake, handshake_type, record_data = check_if_tls_handshake(raw_payload)

        if not is_handshake or record_data is None:
            continue

        # Read the IP addresses and port numbers from this packet.
        # These four values together are like a fingerprint for this connection
        # no two connections on the network share the same combination at the same time.
        client_ip = packet[IP].src
        server_ip = packet[IP].dst
        client_port = packet[TCP].sport
        server_port = packet[TCP].dport

        # A Client Hello means the client is starting a fresh TLS connection
        if handshake_type == 0x01:
            
            # Parse the Client Hello to get the cipher suites and supported groups
            client_hello_data = parse_client_hello(record_data)

            # Store the session under a key, Client Hello: client -> server (src=client, dst=server)
            session_key = (server_ip, server_port, client_ip, client_port)

            # Only store this session if it is not seen before
            if session_key not in tls_sessions:
                tls_sessions[session_key] = {
                    "server_ip"        : server_ip,
                    "server_port"      : server_port,
                    "client_ip"        : client_ip,
                    "offered_suites"   : client_hello_data["cipher_suites"],
                    "supported_groups" : client_hello_data["supported_groups"],
                    "selected_suite"   : None,
                    "has_server_hello" : False,
                    "certificate_der"  : None   # filled in if a Certificate message is captured later

                }

        # A Server Hello means the server has picked one cipher suite from the client's list
        elif handshake_type == 0x02:

            # Parse the Server Hello to get the chosen suite
            server_hello_data = parse_server_hello(record_data)

            # Server Hello: server -> client (src=server, dst=client)
            session_key = (client_ip, client_port, server_ip, server_port)

            # If already saw the Client Hello for this connection, update it
            if session_key in tls_sessions:
                tls_sessions[session_key]["selected_suite"]   = server_hello_data["selected_cipher_suite"]
                tls_sessions[session_key]["has_server_hello"] = True

        elif handshake_type == 0x0B:

            # Certificate comes from server to client
            session_key = (client_ip, client_port, server_ip, server_port)

            # Only store the first certificate seen for this session
            if session_key in tls_sessions and tls_sessions[session_key]["certificate_der"] is None:
                der_bytes = extract_certificate_der_from_packet(raw_payload)
                if der_bytes is not None:
                    tls_sessions[session_key]["certificate_der"] = der_bytes

    # Done walking packets, now turn everything tracked into findings       
    all_findings = []


    # Keep track of which servers are already reported on.
    # only need one finding per server, not one per connection.
    reported_servers = set()

    for session_key, session in tls_sessions.items():

        server_endpoint = (session["server_ip"], session["server_port"])

        if server_endpoint in reported_servers:
            continue

        # Work out what cipher suite was actually used in this session
        algorithm = None
        is_vulnerable = None
        suite_name = None

        if session["selected_suite"] is not None:
            # server's chosen suite
            algorithm, is_vulnerable, suite_name = classify_cipher_suite(session["selected_suite"])

            # TLS 1.3 cipher suites tells nothing about key exchange
            # the suite name only describes symmetric encryption and hashing.
            # Need to look at the supported groups to find out what key exchange algorithm was actually used.
            if algorithm == "TLS13" and session["supported_groups"]:
                algorithm, is_vulnerable = classify_supported_groups(session["supported_groups"])
                suite_name = f"TLS 1.3 with {algorithm}"

        elif session["offered_suites"]:
            # No Server Hello was captured, fall back to what the client offered.
            # Walk through the offered suites and stop at the first vulnerable one
            for offered_suite in session["offered_suites"]:
                algorithm, is_vulnerable, suite_name = classify_cipher_suite(offered_suite)
                if is_vulnerable:
                    break

        if algorithm is None or algorithm == "Unknown":  # Skip this session
            continue

        # Resolve the key size through the three-tier fallback system
        key_size, key_size_source = get_key_size_with_fallback(session["certificate_der"], algorithm, session["server_ip"], session["server_port"])

        # Build the finding dictionary, same as what certificate_analyser produces
        # so it drops straight into the risk engine
        finding = {
            "target"           : f"{session['server_ip']}:{session['server_port']}",
            "client_ip"        : session["client_ip"],
            "algorithm"        : algorithm,
            "cipher_suite"     : suite_name,
            "key_size"         : key_size,
            "vulnerable"       : is_vulnerable,
            "issuer"           : None,  # Not available from PCAP
            "expires"          : None,  # Not available from PCAP
            "has_server_hello" : session["has_server_hello"],
            "source"           : "pcap_handshake"        
        }

        all_findings.append(finding)
        reported_servers.add(server_endpoint)

    return all_findings


# Takes the raw bytes from a TCP packet and checks
# is this a TLS handshake? if yes, is it a Client Hello or Server Hello?
def check_if_tls_handshake(raw_tcp_payload):
    
    # Need at least 6 bytes to check 
    if len(raw_tcp_payload) < 6:
        return False, None, None
    
    content_type = raw_tcp_payload[0]
    if content_type != 0x16:  # 0x16 means Handshake
        return False, None, None
    
    tls_major_version = raw_tcp_payload[1]
    if tls_major_version != 0x03:  # TLS versions start with 0x03
        return False, None, None
    
    record_length = struct.unpack(">H", raw_tcp_payload[3:5])[0]

    if len(raw_tcp_payload) < 5+record_length:
        return False, None, None

    # Record data starts from byte 5
    record_data = raw_tcp_payload[5:5+record_length]

    handshake_type = record_data[0]
    # 0x01 is Client Hello, 0x02 is Server Hello, 0x0B is Certificate
    if handshake_type not in (0x01, 0x02, 0x0B):
        return False, None, None
    
    # All checks passes, this is a TLS handshake
    return True, handshake_type, record_data


# Digs inside a Client Hello record and pulls out two things:
# The list of cipher suites the client offered, and the supported groups from the extensions.
def parse_client_hello(record_data):

    result = {"cipher_suites":[], "supported_groups":[]}

    # The Client Hello body starts at index 4 inside record_data
    # (1 byte handshake type + 3 bytes handshake length = 4 bytes to skip)
    # Then we skip client version (2 bytes) and client random (32 bytes)
    # That puts us at index 38, where the session ID length lives

    session_id_length_index = 38

    try:

        # Make sure it actually contains those many bytes
        if len(record_data) <= session_id_length_index:
            return result
        
        # Get the session ID length to skip those amount of bytes
        session_id_length = record_data[session_id_length_index]

        # After the session ID, the next byte is cipher suites length
        cipher_suites_length_index = session_id_length_index + 1 + session_id_length

        if len(record_data) <= cipher_suites_length_index + 1:
            return result
        
        # Read the cipher suites length (2bytes), big-endian
        cipher_suites_length = struct.unpack(">H", record_data[cipher_suites_length_index : cipher_suites_length_index + 2])[0]

        # The actual cipher suite values start right after the 2-byte length
        cipher_data_start = cipher_suites_length_index + 2
        cipher_data_end = cipher_data_start + cipher_suites_length

        if len(record_data) < cipher_data_end:
            return result
        
        # Each cipher suites is exactly 2 bytes
        for position in range(cipher_data_start, cipher_data_end, 2):
            if position + 2 <= len(record_data):
                suite_value = struct.unpack(">H", record_data[position : position + 2])[0]
                result["cipher_suites"].append(suite_value)

        # Now find the supported_groups extension
        # First skip the compression methods to reach the extensions
        # compression length is 1 byte, it sits straight after the cipher suites data

        compression_length_index = cipher_data_end
        if len(record_data) <= compression_length_index:
            return result
        
        compression_length = record_data[compression_length_index]

        # Extensions length sits right after compression methods
        extensions_length_index = compression_length_index + 1 + compression_length
        if len(record_data) <= extensions_length_index + 1:
            return result
        
        # Read the total extensions length, 2 bytes
        extensions_length = struct.unpack(">H", record_data[extensions_length_index : extensions_length_index + 2])[0]

        # Extensions data starts right after the 2 bytes extensions length
        extensions_start = extensions_length_index + 2
        extensions_end = extensions_start + extensions_length

        # Walk through each extension one by one
        # Each extension has 2 bytes type + 2 bytes length + data
        ext_offset = extensions_start

        while ext_offset + 4 <= min(extensions_end, len(record_data)):

            # Read the extension type, 2 bytes
            ext_type = struct.unpack(">H", record_data[ext_offset : ext_offset + 2])[0]

            # Same for ext length
            ext_length = struct.unpack(">H", record_data[ext_offset + 2 : ext_offset + 4])[0]

            # 0x000A is the supported_groups extension, fixed by IANA (Internet Assigned Numbers Authority), never changes
            if ext_type == 0x000A:

                # Inside supported_groups: 2 bytes for the groups list length
                # then 2 bytes per group
                groups_data_start = ext_offset + 4
                if groups_data_start + 2 <= len(record_data):
                    groups_list_length = struct.unpack(">H", record_data[groups_data_start : groups_data_start + 2])[0]

                    # Read each group, 2 bytes at a time
                    group_offset = groups_data_start + 2
                    group_end = group_offset + groups_list_length

                    while group_offset + 2 <= min(group_end, len(record_data)):
                        group_id = struct.unpack(">H", record_data[group_offset : group_offset + 2])[0]
                        result["supported_groups"].append(group_id)
                        group_offset += 2

                # Found what we came for, no need to keep walking extensions
                break

            # if not, move to the next extension
            # Jump bytes: 2 bytes type + 2 bytes len + the extensions data
            ext_offset += 4 + ext_length

    except(struct.error, IndexError):
        # If something went wrong parsing, return whatever we managed to collect
        pass

    return result


# Same for Server Hello record and pulls out the one cipher suite the server chose
# This was the agreed cipher suite by server from client cipher suites list
def parse_server_hello(record_data):

    result = {"selected_cipher_suite": None}

    # Navigation is identical to Client Hello up to the cipher suite
    session_id_length_index = 38

    try:

        if len(record_data) <= session_id_length_index:
             return result
         
        # Skip the session ID data
        session_id_length = record_data[session_id_length_index]

        selected_suite_index = session_id_length_index + 1 + session_id_length
        
        # Make sure we have 2 bytes available to read the cipher suite
        if len(record_data) < selected_suite_index + 2:
            return result
        
        # Read the server selected cipher suite (2 bytes)
        selected_cipher_suite = struct.unpack(">H", record_data[selected_suite_index : selected_suite_index + 2])[0]

        result["selected_cipher_suite"] = selected_cipher_suite

    except(struct.error, IndexError):

        pass

    return result
