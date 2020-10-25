def get_generic_frame():
    # Returns a list of bytes that make up frame header of a management frame 
    # 0 Default RADIOTAP header
    # 1 Type/Subtype
    # 2 Flags
    # 3 Duration ID
    # 4 Destination address
    # 5 Source address
    # 6 BSSID
    # 7 Sequence control
    generic_frame = []
    generic_frame.append( b'\x00\x00\x08\x00\x00\x00\x00\x00' ) # Default RADIOTAP header
    generic_frame.append( b"\xB0" )                             # Type/Subtype
    generic_frame.append( b"\x00" )                             # Flags
    generic_frame.append( b"\x3A\x01" )                         # Duration ID
    generic_frame.append( b"\x00\x00\x00\x00\x00\x00" )         # Destination address
    generic_frame.append( b"\x00\x00\x00\x00\x00\x00" )         # Source address
    generic_frame.append( b"\x00\x00\x00\x00\x00\x00" )         # BSSID
    generic_frame.append( b"\x01\x00" )                         # Sequence control

    return generic_frame

def get_auth_commit_body():
    # returns the body of the auth-commit frame, with scalar and ECC x,y coords precalculated
    sae_scalar = b"\x5b\x34\xa3\x1c\x47\x36\xd8\xbc\x86\x17\x90\x6d\x58\x55\xf8\x9c\xa4\x40\x57\x68\x22\xbe\x2c\xf1\x3c\xbd\xda\x30\xd8\xa4\xac\xac"

    sae_x = b"\x19\xd9\x12\x50\x9a\x7a\xea\x58\x84\x11\xf1\xd7\x5c\x58\x4d\x72\x25\xc2\xd8\x67\x3c\x1e\x27\x7d\xb0\x73\xe5\xb8\x3b\xa6\x92\xf5"

    sae_y = b"\xa8\xa8\x89\x0e\x95\x75\x1f\x62\xb4\x7c\xe9\x3d\x31\x27\x3f\xf1\x5d\x77\x55\x23\x7f\xd5\xca\x0f\x2e\x1d\xc6\xa4\x4a\xb9\x62\x6b\x6a"

    auth_commit_body  = b"\x10\x00"  # Sequence control
    auth_commit_body += b"\x03\x00"  # Authentication algorithm (SAE)
    auth_commit_body += b"\x01\x00"  # Authentication sequence number
    auth_commit_body += b"\x00\x00"  # Authentication status
    auth_commit_body += b"\x13\x00"  # Group Id = 19
    auth_commit_body += sae_scalar   # Scalar
    auth_commit_body += sae_x        # X-Coordinate ECC
    auth_commit_body += sae_y        # Y-Coordinate ECC



    return auth_commit_body

def get_auth_confirm_body(sequence=b"\x01\x00", status=b"\x00\x00"):
    # Returns the body of the auth-confirm frame
    confirm_key = "\x67\x90\x80\xf4\x69\xa3\x48\x4a\xf8\x6d\xb0\xb4\xba\x2e\x4f\xa4" \
    "\x23\xf6\xc6\xe3\x5e\x96\xfe\x4e\x78\x69\x89\xb7\x7f\xdb\x83\x47"


    auth_confirm_body   = b"\x20\x00"   # Sequence control, last 4 bits are fragment number, first 16 bits are sequence number
    auth_confirm_body  += b"\x03\x00"   # Authentication algorithm (SAE)
    auth_confirm_body  += b"\x02\x00"   # Authentication sequence number
    auth_confirm_body  += b"\x00\x00"   # Authentication status
    auth_confirm_body  += b"\xff\xff"   # send confirm
    auth_confirm_body  += confirm_key # confirm token

    frame[28:30] = status

    return auth_confirm_body


def get_assoc_req_body():
    assoc_req_body   = b"\x04\x31"                   # Fixed Parameters: Capabilities
    assoc_req_body  += b"\x00\01"                    # Fixed Parameters: Status Code
    assoc_req_body  += b"\x00\x01"                   # Fixed Parameters: Association ID
    assoc_req_body  += b"\x00\x00\x00\x00\x00\x00"   # Tagged Parameters Should be 26 bytes+

    return assoc_req_body

def get_assoc_resp_body():
    assoc_resp_body   = b"\x04\x11"                  # Fixed Parameters: Capabilities
    assoc_resp_body  += b"\x00\01"                   # Fixed Parameters: Status Code
    assoc_resp_body  += b"\x00\x01"                  # Fixed Parameters: Association ID
    assoc_resp_body  += b"\x00\x00\x00\x00\x00\x00"  # Tagged Parameters Should be 26 bytes+

    return assoc_req_body

def get_deauth_body():
    deauth_body  = b"\x02\x00"  # Reason code

    return deauth_body

def get_disassoc_body():
    disassoc_body  = b"\x02\x00"  # Reason code

    return disassoc_body
