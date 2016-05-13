#!/usr/bin/python3 -O

import netaddr
import socket
import struct
import sys

from sshtransport import *
import sshmessage

class ScanResult(object):
    def __init__(self):
        self.identification_string = None
        self.kex_init = None


def main():
    for addr in addresses(sys.argv[1:]):
#        try:
            print("Scanning {}:{}".format(*addr))
            result = scan(addr)
            print("protocol version: " + result.identification_string.protoversion)
            print("kex_algorithms:", ", ".join(result.kex_init.kex_algorithms))
            print("server_host_key_algorithms:", ", ".join(result.kex_init.server_host_key_algorithms))
            print("encryption_algorithms_client_to_server:", ", ".join(result.kex_init.encryption_algorithms_c2s))
            print("encryption_algorithms_server_to_client:", ", ".join(result.kex_init.encryption_algorithms_s2c))
            print("mac_algorithms_client_to_server:", ", ".join(result.kex_init.mac_algorithms_c2s))
            print("mac_algorithms_server_to_client:", ", ".join(result.kex_init.mac_algorithms_s2c))
            print("Finished scanning {}:{}\n".format(*addr))
#        except Exception as ex:
#            print("ERROR!", "Unable to scan {}:{}".format(*addr), ex)


def addresses(args):
    for arg in args:
        parts = arg.split(":")
        host_or_cidr = parts[0]
        port = int(parts[1]) if len(parts) >= 2 else 22

        if len(host_or_cidr) == 0:
            raise Exception("empty hostname")

        if len(parts) > 2:
            raise Exception("too many colons")

        if not 0 < port < 65536:
            raise Exception("port out of range")

        if "/" in host_or_cidr:
            for ip in netaddr.IPNetwork(host_or_cidr):
                yield ( str(ip), port )
        else:
            yield ( host_or_cidr, port )

DH_GEX_SHA1 = "diffie-hellman-group-exchange-sha1"
DH_GEX_SHA256 = "diffie-hellman-group-exchange-sha256"

def scan(addr):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect(addr)
        result = ScanResult()
        result.identification_string = IdentificationString(recvfrom=server)

        if result.identification_string.protoversion != "2.0" and result.identification_string.protoversion != '1.99':
            return result

        IdentificationString(protoversion="2.0", softwareversion="SSHLabsScanner_0.1").send(server)
        result.kex_init = sshmessage.KexInit(packet=BinaryPacket(recvfrom=server))

        # Discard first KEX packet. I don't think this is ever GEX, which is all
        # we care about.
        if result.kex_init.first_kex_packet_follows:
            print("discarding first kex packet")
            BinaryPacket(recvfrom=server)

        if DH_GEX_SHA256 in result.kex_init.kex_algorithms or DH_GEX_SHA1 in result.kex_init.kex_algorithms:
            kex_init = result.kex_init.optimal_response()
            kex_init.kex_algorithms = [ DH_GEX_SHA256, DH_GEX_SHA1 ]
            kex_init.to_packet().send(server)
            dh_gex_request = sshmessage.DHGEXRequest(n=1024)
            dh_gex_request.to_packet().send(server)

            dh_gex_group = sshmessage.DHGEXGroup(packet=BinaryPacket(recvfrom=server))
            print(dh_gex_group.prime, dh_gex_group.generator)

        return result
    finally:
        server.close()

if __name__ == "__main__":
    main()
