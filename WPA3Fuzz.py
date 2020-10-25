import logging
import socket
import time
import os
import argparse
import alter_frame

from boofuzz import *
from scapy.all import *

def main():
    parser = argparse.ArgumentParser(
        usage='sudo python3 WPA3Fuzz.py --ap-mac 02:00:00:00:02:00 --sta-mac 02:00:00:00:01:00 --iface wlan1'
    )

    parser.add_argument('--sta-mac',  dest='sta_mac', help='STA MAC address (fuzzer)')
    parser.add_argument('--ap-mac', dest='ap_mac', help='AP MAC address (fuzzed)')
    parser.add_argument('--iface', dest='iface', default='wlan0', help='injection interface')

    args = parser.parse_args()

    if not args.sta_mac:
        parser.error('STA MAC address must be set')
    if not args.iface:
        parser.error('injection interface must be set')
    if not args.ap_mac:
        parser.error('AP MAC address must be set')

    logging.basicConfig(level=logging.INFO)

    connection = SocketConnection(
        host=args.iface,
        proto='wifi',
        ethernet_proto=socket.htons(ETH_P_ALL),
        send_timeout=5.0,
        recv_timeout=5.0
    )

    connection.wifi_dev = args.iface

    target = Target(connection=connection)

    session = Session(
        sleep_time=0.1,
        target=target
    )
    # Import constructframe utility that constructs generic frame and individual frame bodies
    import construct_frame
    generic_frame = construct_frame.get_generic_frame()

    # 0 Default RADIOTAP header
    # 1 Type/Subtype
    # 2 Flags
    # 3 Duration ID
    # 4 Destination address
    # 5 Source address
    # 6 BSSID
    # 7 Sequence control
    generic_frame[4] = generic_frame[6] = bytes.fromhex(args.ap_mac.replace(':', ' '))
    generic_frame[5] = bytes.fromhex(args.sta_mac.replace(':', ' '))
    
    alter_frame.alter_auth_commit(session,generic_frame)
    alter_frame.alter_auth_confirm(session,generic_frame)
    alter_frame.alter_deauth(session,generic_frame)
    ## Remember to alter frame type/subtype

if __name__ == '__main__':
    main()
