import struct 

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
