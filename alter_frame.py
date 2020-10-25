from boofuzz import *
import construct_frame
import callback_functions


def alter_auth_commit(session,generic_frame):
    #auth_commit_frame = generic_frame+get_auth_commit_body()
    generic_frame[1] = b"\xB0" # Subtype authentication
    generic_frame = b''.join(generic_frame)
    auth_commit_body = construct_frame.get_auth_commit_body()
    
    s_initialize('auth-commit: valid')
    s_static(generic_frame)
    s_static(auth_commit_body)
    
    s_initialize('auth-commit: Fuzz Auth Algo')
    s_static(generic_frame)
    s_word(0x0003, fuzzable=True)
    s_static(auth_commit_body[2:])

    s_initialize('auth-commit: Fuzz Auth Sequence')
    s_static(generic_frame)
    s_static(auth_commit_body[:2])
    s_word(0x0000, fuzzable=True)
    s_static(auth_commit_body[4:])
    
    s_initialize('auth-commit: Fuzz Status Code')
    s_static(generic_frame)
    s_static(auth_commit_body[:4])
    s_word(0x0000, fuzzable=True)
    s_static(auth_commit_body[6:])

    s_initialize('auth-commit: Fuzz Group ID')
    s_static(generic_frame)
    s_static(auth_commit_body[:6])
    s_word(0x0013, fuzzable=True)
    s_static(auth_commit_body[8:])

    s_initialize('auth-commit: Fuzz Scalar')
    s_static(generic_frame)
    s_static(auth_commit_body[:8])
    s_word(0x0000, fuzzable=True)
    s_static(auth_commit_body[10:])

    s_initialize('auth-commit: Fuzz FFE')
    s_static(generic_frame)
    s_static(auth_commit_body[:10])
    s_word(0x0000, fuzzable=True)
    s_static(auth_commit_body[12:])

    session.connect(s_get('auth-commit: valid'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-commit: Fuzz Auth Algo'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-commit: Fuzz Auth Sequence'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-commit: Fuzz Status Code'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-commit: Fuzz Group ID'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-commit: Fuzz Scalar'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-commit: Fuzz FFE'), callback=callback_functions.check_auth)    
    
    session.fuzz()

def alter_auth_confirm(session,ap_mac,sta_mac,generic_frame):
    generic_frame[1] = b"\xB0" # Subtype authentication
    generic_frame = b''.join(generic_frame)
    auth_confirm_body = construct_frame.get_auth_confirm_body()
    
    s_initialize('auth-confirm: valid')
    s_static(generic_frame)
    s_static(auth_confirm_body)
    
    s_initialize('auth-confirm: Fuzz Auth Algo')
    s_static(generic_frame)
    s_word(0x0003, fuzzable=True)
    s_static(auth_confirm_body[2:])

    s_initialize('auth-confirm: Fuzz Auth Sequence')
    s_static(generic_frame)
    s_static(auth_confirm_body[:2])
    s_word(0x0000, fuzzable=True)
    s_static(auth_confirm_body[4:])
    
    s_initialize('auth-confirm: Fuzz Status Code')
    s_static(generic_frame)
    s_static(auth_confirm_body[:4])
    s_word(0x0000, fuzzable=True)
    s_static(auth_confirm_body[6:])

    s_initialize('auth-confirm: Fuzz Group ID')
    s_static(generic_frame)
    s_static(auth_confirm_body[:6])
    s_word(0x0013, fuzzable=True)
    s_static(auth_confirm_body[8:])

    s_initialize('auth-confirm: Fuzz Confirm Key')
    s_static(generic_frame)
    s_static(auth_confirm_body[:8])
    s_word(0x0000, fuzzable=True)
    s_static(auth_confirm_body[10:])

    session.connect(s_get('auth-confirm: valid'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-confirm: Fuzz Auth Algo'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-confirm: Fuzz Auth Sequence'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-confirm: Fuzz Status Code'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-confirm: Fuzz Group ID'), callback=callback_functions.check_auth)
    session.connect(s_get('auth-confirm: Fuzz Confirm Key'), callback=callback_functions.check_auth)
    
    session.fuzz()


def alter_deauth(session,generic_frame):
    generic_frame[1] = b"\xC0" # Subtype deauthentication
    deauth_frame = b''.join(generic_frame)+construct_frame.get_deauth_body()
    
    s_initialize('deauth: valid')
    s_static(deauth_frame)

    # Non-PMF Deauthentication
    s_initialize('deauth: Fuzz reason code')
    s_static(deauth_frame[:-2])
    s_byte(0x00, fuzzable=True)

    session.connect(s_get('deauth: valid'), callback=callback_functions.check_auth)
    session.connect(s_get('deauth: Fuzz reason code'), callback=callback_functions.check_auth)
    session.fuzz()
