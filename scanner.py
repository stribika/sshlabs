#!/usr/bin/python3 -O

import math
import netaddr
import random
import socket
import struct
import sys

import analysis
from sshtransport import *
import sshmessage

csprng = random.SystemRandom()

class ScanResult(object):
    def __init__(self):
        self.identification_string = None
        self.kex_init = None
        self.dh_gex_groups = set()
        self.issues = []


def main():
    for addr in addresses(sys.argv[1:]):
#        try:
            print("Scanning {}:{}".format(*addr))
            result = scan(addr)
            print(result.identification_string)
            print(result.kex_init)
            result.issues += analysis.analyze_kex_init(result.kex_init)
            if supports_dh_gex(result.kex_init):
#                collect_dh_groups(result, addr)
                result.issues += analysis.analyze_dh_groups(result.dh_gex_groups)
            print("\n".join([ str(issue) for issue in result.issues ]))
            print("score", analysis.score(result.issues))
            print("Finished scanning {}:{}\n".format(*addr))
#        except Exception as ex:
#            print("ERROR!", "Unable to scan {}:{}".format(*addr), ex)

def collect_dh_groups(result, addr):
    known_count = len(result.dh_gex_groups)
    no_new_count = 1
    for dh_group_size in range(2**10, 2**13 + 2**9, 2**9):
        no_new_count -= 1 # a hack to try each size at least once
        probability_of_more = (known_count / (known_count + 1))**no_new_count
        while probability_of_more > 0.05:
            dh_result = scan(addr, dh_group_size, True)
            if dh_result.dh_gex_groups.issubset(result.dh_gex_groups):
                no_new_count += 1
            else:
                result.dh_gex_groups.update(dh_result.dh_gex_groups)
                known_count = len(result.dh_gex_groups)
                no_new_count = 0
            probability_of_more = (known_count / (known_count + 1))**no_new_count

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
HOST_KEY_RSA_SHA1 = "ssh-rsa"
HOST_KEY_RSA_SHA256 = "rsa-sha2-256"
HOST_KEY_RSA_SHA512 = "rsa-sha2-512"

def scan(addr, dh_group_size=1024, quick=False):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect(addr)
        ssh_server = SSHSocket(server)
        result = ScanResult()
        result.identification_string = ssh_server.recv()

        if result.identification_string.protoversion != "2.0" and result.identification_string.protoversion != '1.99':
            return result

        ssh_server.send(IdentificationString(
            protoversion="2.0",
            softwareversion="SSHLabsScanner_0.1"
        ))
        result.kex_init = sshmessage.KexInit(packet=ssh_server.recv())

        # Discard first KEX packet. I don't think this is ever GEX, which is all
        # we care about.
        if result.kex_init.first_kex_packet_follows:
            print("discarding first kex packet")
            ssh_server.recv()

        
        kex_init = result.kex_init.optimal_response()

        if supports_rsa(result.kex_init):
            kex_init.server_host_key_algorithms = [
                HOST_KEY_RSA_SHA512,
                HOST_KEY_RSA_SHA256,
                HOST_KEY_RSA_SHA1
            ]    

        if supports_dh_gex(result.kex_init):
            dh_gex_group = get_dh_gex_group(ssh_server, kex_init, dh_group_size)
            result.dh_gex_groups.add(dh_gex_group)
            # No need to do this again.
            if quick:
                return result
            dh_secret = csprng.randint(0, dh_gex_group.prime - 1)
            dh_public = pow(dh_gex_group.generator, dh_secret, dh_gex_group.prime)
            ssh_server.send(sshmessage.DHGEXInit(e=dh_public).to_packet())
            dh_gex_reply = sshmessage.DHGEXReply(packet=ssh_server.recv())
            shared_secret = pow(dh_gex_reply.f, dh_secret, dh_gex_group.prime)
            server_public_key = sshmessage.RSAPublicKey(data=dh_gex_reply.server_public_key)
            print(math.ceil(math.log(server_public_key.modulus, 2)))

        # TODO get host public key from hosts that don't support DH GEX

        return result
    finally:
        server.close()

def supports_rsa(kex_init):
    rsa = set([ HOST_KEY_RSA_SHA1, HOST_KEY_RSA_SHA256, HOST_KEY_RSA_SHA512 ])
    return not rsa.isdisjoint(kex_init.server_host_key_algorithms)

def supports_dh_gex(kex_init):
    return DH_GEX_SHA256 in kex_init.kex_algorithms or DH_GEX_SHA1 in kex_init.kex_algorithms

def get_dh_gex_group(ssh_server, kex_init, dh_group_size):
    kex_init.kex_algorithms = [ DH_GEX_SHA256, DH_GEX_SHA1 ]
    ssh_server.send(kex_init.to_packet())
    dh_gex_request = sshmessage.DHGEXRequest(n=dh_group_size)
    ssh_server.send(dh_gex_request.to_packet())
    return sshmessage.DHGEXGroup(packet=ssh_server.recv())
    

if __name__ == "__main__":
    main()
