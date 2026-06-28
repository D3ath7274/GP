#!/usr/bin/env python3
"""
ipsctl — send a control command to the IPS controller over UDP 9999.

Replaces fragile `nc -u` one-liners (netcat is often missing / BSD-vs-GNU on the t530).
Pure Python, works anywhere Python runs.

Run it ON the controller (defaults to 127.0.0.1), or from another box with IPS_HOST set.

Examples:
  python3 ipsctl.py CONTROL:DETECT:ON
  python3 ipsctl.py CONTROL:DETECT:OFF
  python3 ipsctl.py CONTROL:ML:OBSERVE
  python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80
  python3 ipsctl.py CONTROL:ML:OFF
  python3 ipsctl.py CONTROL:ML:FLAG:0.60
  python3 ipsctl.py CONTROL:ML:BLOCK:0.80
  python3 ipsctl.py CONTROL:CLEAR              # release ALL confirmed/suspicion state
  python3 ipsctl.py CONTROL:CLEAR:10.0.0.1     # release one source
  python3 ipsctl.py CONTROL:UNBLOCK:10.0.0.1   # remove a block
  python3 ipsctl.py CONTROL:ROTATE:test.csv    # save+rotate the dataset
  IPS_HOST=192.168.1.65 python3 ipsctl.py CONTROL:DETECT:ON   # from the Mininet VM

Env: IPS_HOST (default 127.0.0.1), IPS_PORT (default 9999).
"""
import os
import socket
import sys


def main():
    if len(sys.argv) < 2:
        print("usage: python3 ipsctl.py <COMMAND>   e.g. CONTROL:DETECT:ON")
        sys.exit(1)
    host = os.environ.get('IPS_HOST', '127.0.0.1')
    port = int(os.environ.get('IPS_PORT', '9999'))
    msg = ' '.join(sys.argv[1:]).strip()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg.encode('utf-8'), (host, port))
    s.close()
    print(f"sent -> {host}:{port}   {msg}")


if __name__ == '__main__':
    main()
