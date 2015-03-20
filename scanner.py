#!/usr/bin/python3

import netaddr
import socket
import struct
import sys

class ScanResult(object):
    pass

def main():
    for addr in addresses(sys.argv[1:]):
        try:
            print("Scanning {}:{}".format(*addr))
            result = scan(addr)
            print("kex_algorithms:", ", ".join(result.kex_algorithms))
            print("server_host_key_algorithms:", ", ".join(result.server_host_key_algorithms))
            print("encryption_algorithms_client_to_server:", ", ".join(result.encryption_algorithms_client_to_server))
            print("encryption_algorithms_server_to_client:", ", ".join(result.encryption_algorithms_server_to_client))
            print("mac_algorithms_client_to_server:", ", ".join(result.mac_algorithms_client_to_server))
            print("mac_algorithms_server_to_client:", ", ".join(result.mac_algorithms_server_to_client))
            print("Finished scanning {}:{}\n".format(*addr))
        except Exception as ex:
            print("ERROR!", "Unable to scan {}:{}".format(*addr), ex)


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

def scan(addr):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.connect(addr)
        result = ScanResult()
        ( result.protoversion, result.softwareversion ) = recv_identification_string(server)

        if result.protoversion != "2.0":
            return result

        send_identification_string(server, "2.0", "SSHLabsScanner_0.1")
        ( payload, padding, mac ) = recv_binary_packet(server, 0)
        ( msg_type, cookie ) = struct.unpack(">B16s", payload[:17])

        if msg_type != SSH_MSG_KEXINIT:
            raise Exception("SSH_MSG_KEXINIT expected")

        payload = payload[17:]
        ( payload, result.kex_algorithms ) = parse_name_list(payload)
        ( payload, result.server_host_key_algorithms ) = parse_name_list(payload)
        ( payload, result.encryption_algorithms_client_to_server ) = parse_name_list(payload)
        ( payload, result.encryption_algorithms_server_to_client ) = parse_name_list(payload)
        ( payload, result.mac_algorithms_client_to_server ) = parse_name_list(payload)
        ( payload, result.mac_algorithms_server_to_client ) = parse_name_list(payload)
        ( payload, result.compression_algorithms_client_to_server ) = parse_name_list(payload)
        ( payload, result.compression_algorithms_server_to_client ) = parse_name_list(payload)
        ( payload, result.languages_client_to_server ) = parse_name_list(payload)
        ( payload, result.languages_server_to_client ) = parse_name_list(payload)

        return result

def recv_identification_string(server):
    ident_str = b""
    while b"\r\n" not in ident_str:
        ident_str += server.recv(64)

    ident_str = ident_str[:-2].decode("ASCII")

    if not ident_str.isprintable():
        raise Exception("non-printable characters in the identification string")

    ident_str = ident_str.split("-", 2)

    if ident_str[0] != "SSH":
        raise Exception("invalid protocol")

    if len(ident_str) != 3:
        raise Exception("exactly 3 dash separated parts expected in the identification string")

    return ident_str[1:]

def send_identification_string(server, protoversion, softwareversion):
    server.send(("-".join([ "SSH", protoversion, softwareversion ]) + "\r\n").encode("ASCII"))

def recv_binary_packet(server, mac_length):
    header = recv_bytes(server, 5)
    ( packet_length, padding_length ) = struct.unpack(">LB", header)
    body_fmt = "{}s{}s{}s".format(packet_length - padding_length - 1, padding_length, mac_length)
    body = recv_bytes(server, struct.calcsize(body_fmt))
    ( payload, padding, mac ) = struct.unpack(body_fmt, body)
    return ( payload, padding, mac )

def parse_name_list(buf):
    length = struct.unpack(">L", buf[:4])[0]
    return ( buf[4 + length:], buf[4:4 + length].decode("ASCII").split(",") )

def recv_bytes(server, n):
    response = b""
    while len(response) < n:
        response += server.recv(n - len(response))
    return response

if __name__ == "__main__":
    main()
