import struct 
import csv
from pathlib import Path

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

def classify_cipher_suite(suite_value):

    # Look up this suite value in the loaded dictionary
    # Used .get(), to return None instead of crashing if the suite is not in the list
    suite_entry = ALL_CIPHER_SUITES.get(suite_value)

    # This covers private use ranges and any suites added after the CSV was downloaded
    if suite_entry is None:
        return "Unknown", None, f"Unknown suite (0x{suite_value:04X})"
    
    algorithm = suite_entry["key_exchange"]
    is_vulnerable = suite_entry["quantum_vulnerable"]
    suite_name = suite_entry["name"]

    return algorithm, is_vulnerable, suite_name


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

    # Record data starts from byte 5
    record_data = raw_tcp_payload[5:5+record_length]

    handshake_type = record_data[0]
    # 1 is Client Hello, 2 is Server Hello
    if handshake_type not in (0x01, 0x02):
        return False, None, None
    

    # All checks passes, this is a TLS handshake
    return True, handshake_type, record_data


# Digs inside a Client Hello record and pulls out two things:
# The list of cipher suites the client offered, and the supported groups from the extensions.
def parse_client_hello(record_data):

    result = {"cipher_suites":[], "supported_groups":[]}

    try:

        # The Client Hello body starts at index 4 inside record_data
        # (1 byte handshake type + 3 bytes handshake length = 4 bytes to skip)
        # Then we skip client version (2 bytes) and client random (32 bytes)
        # That puts us at index 38, where the session ID length lives

        session_id_length_index = 38

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
        
        # Each cipher suites is eaxctly 2 bytes
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

            # 0x000A is the supported_groups extension, this is what we need and it s completely fixed. The IANA (Internet Assigned Numbers Authority) assigned it.
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

    try:

        # Navigation is identical to Client Hello up to the cipher suite
        session_id_length_index = 38

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
