import logging
logging.basicConfig(level=logging.INFO)





def check_frame_subtype(pkt):
    if pkt[0:1] == b"\xb0":
        logging.info('received auth response')
        return 'auth'
    elif pkt[0:1] == b'\x40':
        logging.info('received probe request')
        return 'probe request'
    elif pkt[0:1] == b'\x50':
        logging.info('received probe response')
        return 'probe response'
    elif pkt[0:1] == b'\x00':
        logging.info('received assoc request')
        return 'assoc request'
    elif pkt[0:1] == b'\x00':
        logging.info('received assoc response')
        return 'assoc response'
    elif pkt[0:1] == b'\x80':
        logging.info('received beacon frame')
        return 'beacon'
    elif pkt[0:1] == b'\xC0':
        logging.info('received deauthentication frame')
        logging.info('Destination address:')
        logging.info(pkt[4:10])
        return 'deauthentication'


def check_response(target, fuzz_data_logger, session, *args, **kwargs):
    header_length = struct.unpack('h', pkt[2:4])[0]
    pkt = pkt[header_length:]
    #create function to check if management type frame
    if check_frame_subtype(pkt) == 'auth':
        logging.info(pkt)


def check_auth(target, fuzz_data_logger, session, *args, **kwargs):
    # logging.info('last_send: {}'.format(session.last_send))
    # logging.info('last_recv: {}'.format(session.last_recv))
    def anti_clogging_token_response(pkt):
        header_length = struct.unpack('h', pkt[2:4])[0]
        pkt = pkt[header_length:]

        if check_frame_subtype(pkt) == 'auth':
            logging.info(pkt)

        return (len(pkt) >= 30 and pkt[0:1] == b"\xb0"
                and pkt[28:30] == b"\x4c\x00")

    for pkt in (session.last_recv, target.recv(1024)):
        if pkt:
            ans = anti_clogging_token_response(pkt)
            logging.info(f'got {len(pkt)} bytes')
            if ans:
                logging.info('got anti clogging token response')
                logging.info(pkt[32:])
                return

# add is_alive