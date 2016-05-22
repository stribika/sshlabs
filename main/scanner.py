#!/usr/bin/python3 -O

import argparse
import json
import math
import netaddr
import random
import socket
import struct
import sys

from algorithms import *
import analysis
from sshtransport import *
import sshmessage

csprng = random.SystemRandom()

class ScanResult(object):
    def __init__(self):
        self.identification_string = None
        self.kex_init = None
        self.dh_gex_groups = set()
        self.server_public_key = None
        self.issues = []

class JSONOutput(object):
    def begin(self):
        self.first = True
        sys.stdout.write("[")

    def print_scan_start(self, host, port):
        self.jsonobj = {
            "host": host,
            "port": port,
            "issues": [],
        }

    def print_identification(self, id_str):
        self.jsonobj["identification_string"] = id_str

    def print_algorithms(self, kex_init):
        self.jsonobj["kex_init"] = kex_init

    def print_issue(self, issue, details, instructions):
        if not details:
            issue.details = None

        if not instructions:
            issue.instructions = None

        self.jsonobj["issues"].append(issue)
        
    def print_final_score(self, score):
        if not self.first:
            sys.stdout.write(",")

        self.first = False
        self.jsonobj["score"] = score
        json.dump(self.jsonobj, sys.stdout, default=lambda x: x.to_dict())

    def end(self):
        print("]")

class TextOutput(object):
    def begin(self): pass

    def print_scan_start(self, host, port):
        self.host = host
        self.port = port
        print("Scanning {}:{} ...".format(host, port))

    def print_identification(self, idstr):
        print(idstr)

    def print_algorithms(self, kex_init):
        print(kex_init)

    def print_issue(self, issue, details, instructions):
        print(issue)

        if details:
            print(issue.details)

        if instructions:
            print(issue.instructions)

    def print_final_score(self, score):
        print("Final score for {}:{} is".format(self.host, self.port), score)
        self.host = None
        self.port = None

    def end(self): pass

def parse_args():
    parser = argparse.ArgumentParser(description="SSHLabs Scanner")
    parser.add_argument("-a", "--algorithms",   action="store_true", help="show all supported algorithms")
    parser.add_argument("-d", "--details",      action="store_true", help="show detailed findings")
    parser.add_argument("-f", "--fast",         action="store_true", help="sacrifice accuracy for speed")
    parser.add_argument("-i", "--instructions", action="store_true", help="show instructions to fix (assuming UNIX and OpenSSH)")
    parser.add_argument("-j", "--json",         action="store_true", help="generate JSON output")
    ( args, addrs ) = parser.parse_known_args()
    args.addresses = addrs
    return args

def main(args=None, output=None):
    if not args:
        args = parse_args()

    if not output:
        output = JSONOutput() if args.json else TextOutput()

    output.begin()

    for addr in addresses(args.addresses):
#        try:
            output.print_scan_start(addr[0], addr[1])
            result = scan(addr)
            
            if args.algorithms:
                output.print_identification(result.identification_string)
                output.print_algorithms(result.kex_init)
            
            result.issues += analysis.analyze_kex_init(result.kex_init)
            
            if supports_dh_gex(result.kex_init):
                collect_dh_groups(result, addr)
                result.issues += analysis.analyze_dh_groups(result.dh_gex_groups, args.fast)

            for issue in result.issues:
                output.print_issue(issue, args.details, args.instructions)

            output.print_final_score(max(0, 10 - analysis.score(result.issues)))
#        except Exception as ex:
#            print("ERROR!", "Unable to scan {}:{}".format(*addr), ex)
    
    output.end()

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
                SIGN_RSA_SHA512,
                SIGN_RSA_SHA256,
                SIGN_RSA_SHA1
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
            
            # TODO gather other things?

            if supports_rsa(result.kex_init):
                result.server_public_key = sshmessage.RSAPublicKey(data=dh_gex_reply.server_public_key)

        # TODO get host public key from hosts that don't support DH GEX

        return result
    finally:
        server.close()

def supports_rsa(kex_init):
    rsa = set([ SIGN_RSA_SHA1, SIGN_RSA_SHA256, SIGN_RSA_SHA512 ])
    return not rsa.isdisjoint(kex_init.server_host_key_algorithms)

def supports_dh_gex(kex_init):
    return KEX_DH_GEX_SHA256 in kex_init.kex_algorithms or KEX_DH_GEX_SHA1 in kex_init.kex_algorithms

def get_dh_gex_group(ssh_server, kex_init, dh_group_size):
    kex_init.kex_algorithms = [ KEX_DH_GEX_SHA256, KEX_DH_GEX_SHA1 ]
    ssh_server.send(kex_init.to_packet())
    dh_gex_request = sshmessage.DHGEXRequest(n=dh_group_size)
    ssh_server.send(dh_gex_request.to_packet())
    return sshmessage.DHGEXGroup(packet=ssh_server.recv())
    

if __name__ == "__main__":
    main()
