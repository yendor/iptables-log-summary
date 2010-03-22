#!/usr/bin/env python

# IN= OUT=eth0 SRC=10.11.19.196 DST=10.16.220.132 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=964 DF PROTO=TCP SPT=45179 DPT=3306 WINDOW=5840 RES=0x00 SYN URGP=0
# IN= OUT=eth0 SRC=10.11.19.194 DST=10.6.171.68 LEN=58 TOS=0x00 PREC=0x00 TTL=64 ID=60930 PROTO=UDP SPT=32802 DPT=53 LEN=38
import re, sys, os

def main():
    if os.path.exists("/var/log/messages"):
        lines = open("/var/log/messages", "r").readlines()
    else:
        lines = sys.stdin.readlines()

    ignoredevs = []
    ports = {}

    for line in lines:
        # TCP log line regex
        matches = re.search("IN=([^ ]*) OUT=([^ ]*) SRC=([^ ]*) DST=([^ ]*) LEN=([^ ]*) TOS=([^ ]*) PREC=([^ ]*) TTL=([^ ]*) ID=([^ ]*) (?:DF)? PROTO=([^ ]*) SPT=([^ ]*) DPT=([^ ]*) WINDOW=([^ ]*) RES=([^ ]*) SYN URGP=([^ ]*)", line.strip())

        if matches is None:
            # UDP log line regex
            matches = re.search("IN=([^ ]*) OUT=([^ ]*) SRC=([^ ]*) DST=([^ ]*) LEN=([^ ]*) TOS=([^ ]*) PREC=([^ ]*) TTL=([^ ]*) ID=([^ ]*) (?:DF)? PROTO=([^ ]*) SPT=([^ ]*) DPT=([^ ]*)", line.strip())

        if matches is None:
            continue

        dev=matches.group(2)
        toport=matches.group(12)
        toaddr=matches.group(4)
        toproto=matches.group(10)

        if dev in ignoredevs:
            continue

        if (toport, toproto, dev) not in ports.keys():
            ports[(toport, toproto, dev)] = 0

        ports[(toport, toproto, dev)] = ports[(toport, toproto, dev)] + 1

    for port, proto, dev in ports.keys():
        print "There have been %d connections to %s/%s (%s)" % (ports[(port, proto, dev)], port, proto, dev)

if __name__ == "__main__":
    # assert("smtp" == getServiceName("25", "tcp"))
    # assert("ssh" == getServiceName("22", "tcp"))
    # assert("mysql" == getServiceName("3306", "tcp"))
    main()
