#!/usr/bin/python3 -O

import netaddr
import socket
import struct
import sys

class ScanResult(object):
    def __init__(self):
        self.identification_string = None
        self.kex_init = None

class IdentificationString(object):
    def __init__(self, protoversion = None, softwareversion = None):
        self.protoversion = protoversion
        self.softwareversion = softwareversion

class KexInit(object):
    def __init__(self):
        self.cookie = None
        self.kex_algorithms = []
        self.server_host_key_algorithms = []
        self.encryption_algorithms_client_to_server = []
        self.encryption_algorithms_server_to_client = []
        self.mac_algorithms_client_to_server = []
        self.mac_algorithms_server_to_client = []
        self.compression_algorithms_client_to_server = []
        self.compression_algorithms_server_to_client = []
        self.languages_client_to_server = []
        self.languages_server_to_client = []
        self.first_kex_packet_follows = None
        self.reserved = None

    def clone(self):
        clone = KexInit()
        clone.cookie = self.cookie
        clone.kex_algorithms = list(self.kex_algorithms)
        clone.server_host_key_algorithms = list(self.server_host_key_algorithms)
        clone.encryption_algorithms_client_to_server = list(self.encryption_algorithms_client_to_server)
        clone.encryption_algorithms_server_to_client = list(self.encryption_algorithms_server_to_client)
        clone.mac_algorithms_client_to_server = list(self.mac_algorithms_client_to_server)
        clone.mac_algorithms_server_to_client = list(self.mac_algorithms_server_to_client)
        clone.compression_algorithms_client_to_server = list(self.compression_algorithms_client_to_server)
        clone.compression_algorithms_server_to_client = list(self.compression_algorithms_server_to_client)
        clone.languages_client_to_server = list(self.languages_client_to_server)
        clone.languages_server_to_client = list(self.languages_server_to_client)
        clone.first_kex_packet_follows = self.first_kex_packet_follows
        clone.reserved = self.reserved
        return clone
 
    def parse(self, payload):
        ( msg_type, self.cookie ) = struct.unpack(">B16s", payload[:17])
    
        if msg_type != SSH_MSG_KEXINIT:
            raise Exception("SSH_MSG_KEXINIT expected")
    
        payload = payload[17:]
        ( payload, self.kex_algorithms ) = parse_name_list(payload)
        ( payload, self.server_host_key_algorithms ) = parse_name_list(payload)
        ( payload, self.encryption_algorithms_client_to_server ) = parse_name_list(payload)
        ( payload, self.encryption_algorithms_server_to_client ) = parse_name_list(payload)
        ( payload, self.mac_algorithms_client_to_server ) = parse_name_list(payload)
        ( payload, self.mac_algorithms_server_to_client ) = parse_name_list(payload)
        ( payload, self.compression_algorithms_client_to_server ) = parse_name_list(payload)
        ( payload, self.compression_algorithms_server_to_client ) = parse_name_list(payload)
        ( payload, self.languages_client_to_server ) = parse_name_list(payload)
        ( payload, self.languages_server_to_client ) = parse_name_list(payload)
        ( payload, self.first_kex_packet_follows ) = parse_boolean(payload)
        ( payload, self.reserved ) = parse_uint32(payload)
    
        if self.reserved != 0:
            print("WARNING! Reserved field not zero.")
        
        if len(payload) > 0:
            print("WARNING! Extra bytes after SSH_MSG_KEXINIT.")

    def get_bytes(self):
        payload = struct.pack(">B16s", SSH_MSG_KEXINIT, self.cookie)
        payload += name_list_bytes(self.kex_algorithms)
        payload += name_list_bytes(self.server_host_key_algorithms)
        payload += name_list_bytes(self.encryption_algorithms_client_to_server)
        payload += name_list_bytes(self.encryption_algorithms_server_to_client)
        payload += name_list_bytes(self.mac_algorithms_client_to_server)
        payload += name_list_bytes(self.mac_algorithms_server_to_client)
        payload += name_list_bytes(self.compression_algorithms_client_to_server)
        payload += name_list_bytes(self.compression_algorithms_server_to_client)
        payload += name_list_bytes(self.languages_client_to_server)
        payload += name_list_bytes(self.languages_server_to_client)
        payload += boolean_bytes(self.first_kex_packet_follows)
        payload += uint32_bytes(self.reserved)
        return payload

def main():
    for addr in addresses(sys.argv[1:]):
#        try:
            print("Scanning {}:{}".format(*addr))
            result = scan(addr)
            print("protocol version: " + result.identification_string.protoversion)
            print("kex_algorithms:", ", ".join(result.kex_init.kex_algorithms))
            print("server_host_key_algorithms:", ", ".join(result.kex_init.server_host_key_algorithms))
            print("encryption_algorithms_client_to_server:", ", ".join(result.kex_init.encryption_algorithms_client_to_server))
            print("encryption_algorithms_server_to_client:", ", ".join(result.kex_init.encryption_algorithms_server_to_client))
            print("mac_algorithms_client_to_server:", ", ".join(result.kex_init.mac_algorithms_client_to_server))
            print("mac_algorithms_server_to_client:", ", ".join(result.kex_init.mac_algorithms_server_to_client))
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

SSH_MSG_KEXINIT = 20

DH_GEX_SHA1 = "diffie-hellman-group-exchange-sha1"
DH_GEX_SHA256 = "diffie-hellman-group-exchange-sha256"

def scan(addr):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect(addr)
        result = ScanResult()
        result.identification_string = recv_identification_string(server)

        if result.identification_string.protoversion != "2.0" and result.identification_string.protoversion != '1.99':
            return result

        send_identification_string(server, "2.0", "SSHLabsScanner_0.1")
        ( payload, padding, mac ) = recv_binary_packet(server, 0)
        result.kex_init = KexInit()
        result.kex_init.parse(payload)

        # Discard first KEX packet. I don't think this is ever GEX, which is all
        # we care about.
        if result.kex_init.first_kex_packet_follows:
            print("discarding first kex packet")
            ( payload, padding, mac ) = recv_binary_packet(server, 0)

        if DH_GEX_SHA256 in result.kex_init.kex_algorithms or DH_GEX_SHA1 in result.kex_init.kex_algorithms:
            kex_init = result.kex_init.clone()
            kex_init.kex_algorithms = [ DH_GEX_SHA256, DH_GEX_SHA1 ]
            kex_init.first_kex_packet_follows = False
            kex_init.reserved = 0
            send_binary_packet(server, kex_init.get_bytes(), b'')

            ( payload, padding, mac ) = recv_binary_packet(server, 0)
            print(payload)

        return result
    finally:
        server.close()

def recv_identification_string(server):
    ident_str = b""
    while b"\n" not in ident_str:
        ident_str += server.recv(64)

    ident_str = ident_str[:-1].decode("ASCII")

    ident_str = ident_str.split("-", 2)

    if ident_str[0] != "SSH":
        raise Exception("invalid protocol")

    if len(ident_str) != 3:
        raise Exception("exactly 3 dash separated parts expected in the identification string")

    result = IdentificationString()
    ( result.protoversion, result.softwareversion ) = ident_str[1:]
    return result

def send_identification_string(server, protoversion, softwareversion):
    server.send(("-".join([ "SSH", protoversion, softwareversion ]) + "\r\n").encode("ASCII"))

def recv_binary_packet(server, mac_length):
    header = recv_bytes(server, 5)
    ( packet_length, padding_length ) = struct.unpack(">LB", header)

    if padding_length < 4:
        print("WARNING! Less than 4 bytes of padding in binary packet.")

    body_fmt = "{}s{}s{}s".format(packet_length - padding_length - 1, padding_length, mac_length)
    body = recv_bytes(server, struct.calcsize(body_fmt))
    ( payload, padding, mac ) = struct.unpack(body_fmt, body)
    return ( payload, padding, mac )

def send_binary_packet(server, payload, mac):
    padding_length = 8 - (5 + len(payload) % 8)
    if padding_length < 4:
        padding_length += 8
    padding = padding_length * b'\x00'
    header = struct.pack(">LB", len(payload) + padding_length + 1, padding_length)
    server.send(header + payload + padding + mac)

def parse_name_list(buf):
    length = struct.unpack(">L", buf[:4])[0]
    return ( buf[4 + length:], buf[4:4 + length].decode("ASCII").split(",") )

def name_list_bytes(name_list):
    s = ",".join(name_list)
    return struct.pack(">L", len(s)) + s.encode("ASCII")

def parse_boolean(buf):
    return ( buf[1:], buf[0] != 0 )

def boolean_bytes(boolean):
    return b'\x01' if boolean else b'\x00' 

def parse_uint32(buf):
    return ( buf[4:], struct.unpack(">L", buf[:4])[0] )

def uint32_bytes(uint32):
    return struct.pack(">L", uint32)

def recv_bytes(server, n):
    response = b""
    while len(response) < n:
        buf = server.recv(n - len(response))
        response += buf
        if len(buf) > 0:
            print("received", len(response), "of", n, "bytes")
    return response

if __name__ == "__main__":
    main()
