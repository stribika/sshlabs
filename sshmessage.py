"""
This might look like an SSH protocol implementation. IT IS NOT. It's not even
remotely secure. Nothing is verified, nothing is random. DO NOT USE.
"""

import struct

import sshtransport
import sshtype

SSH_MSG_KEXINIT                = 20
SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30
SSH_MSG_KEX_DH_GEX_GROUP       = 31
SSH_MSG_KEX_DH_GEX_INIT        = 32
SSH_MSG_KEX_DH_GEX_REPLY       = 33
SSH_MSG_KEX_DH_GEX_REQUEST     = 34

def message_from_packet(binpkt):
    message_types = {
        SSH_MSG_KEXINIT: KexInit,
        SSH_MSG_KEX_DH_GEX_REQUEST: DHGEXRequest,
        SSH_MSG_KEX_DH_GEX_GROUP: DHGEXGroup,
    }
    return message_types[binpkt.payload[0]](packet=binpkt)

class KexInit(object):
    def __init__(self, **kwargs):
        if "packet" in kwargs:
            self.__parse(kwargs["packet"].payload)
        else:
            self.cookie                     = kwargs.get("cookie", b"\x00" * 16)
            self.kex_algorithms             = kwargs.get("kex_algorithms", [])
            self.server_host_key_algorithms = kwargs.get("server_host_key_algorithms", [])
            self.encryption_algorithms_c2s  = kwargs.get("encryption_algorithms_c2s", [])
            self.encryption_algorithms_s2c  = kwargs.get("encryption_algorithms_s2c", [])
            self.mac_algorithms_c2s         = kwargs.get("mac_algorithms_c2s", [])
            self.mac_algorithms_s2c         = kwargs.get("mac_algorithms_s2c", [])
            self.compression_algorithms_c2s = kwargs.get("compression_algorithms_c2s", [])
            self.compression_algorithms_s2c = kwargs.get("compression_algorithms_s2c", [])
            self.languages_c2s              = kwargs.get("languages_c2s", [])
            self.languages_s2c              = kwargs.get("languages_s2c", [])
            self.first_kex_packet_follows   = kwargs.get("first_kex_packet_follows", False)
            self.reserved                   = kwargs.get("reserved", 0)

    def __parse(self, payload):
        ( msg_type, self.cookie ) = struct.unpack(">B16s", payload[:17])
    
        if msg_type != SSH_MSG_KEXINIT:
            raise Exception("SSH_MSG_KEXINIT expected")
    
        payload = payload[17:]
        ( payload, self.kex_algorithms ) = sshtype.parse_name_list(payload)
        ( payload, self.server_host_key_algorithms ) = sshtype.parse_name_list(payload)
        ( payload, self.encryption_algorithms_c2s ) = sshtype.parse_name_list(payload)
        ( payload, self.encryption_algorithms_s2c ) = sshtype.parse_name_list(payload)
        ( payload, self.mac_algorithms_c2s ) = sshtype.parse_name_list(payload)
        ( payload, self.mac_algorithms_s2c ) = sshtype.parse_name_list(payload)
        ( payload, self.compression_algorithms_c2s ) = sshtype.parse_name_list(payload)
        ( payload, self.compression_algorithms_s2c ) = sshtype.parse_name_list(payload)
        ( payload, self.languages_c2s ) = sshtype.parse_name_list(payload)
        ( payload, self.languages_s2c ) = sshtype.parse_name_list(payload)
        ( payload, self.first_kex_packet_follows ) = sshtype.parse_boolean(payload)
        ( payload, self.reserved ) = sshtype.parse_uint32(payload)
    
        if self.reserved != 0:
            print("WARNING! Reserved field not zero.")
        
        if len(payload) > 0:
            print("WARNING! Extra bytes after SSH_MSG_KEXINIT.")

    def to_packet(self):
        payload = struct.pack(">B16s", SSH_MSG_KEXINIT, self.cookie)
        payload += sshtype.name_list_bytes(self.kex_algorithms)
        payload += sshtype.name_list_bytes(self.server_host_key_algorithms)
        payload += sshtype.name_list_bytes(self.encryption_algorithms_c2s)
        payload += sshtype.name_list_bytes(self.encryption_algorithms_s2c)
        payload += sshtype.name_list_bytes(self.mac_algorithms_c2s)
        payload += sshtype.name_list_bytes(self.mac_algorithms_s2c)
        payload += sshtype.name_list_bytes(self.compression_algorithms_c2s)
        payload += sshtype.name_list_bytes(self.compression_algorithms_s2c)
        payload += sshtype.name_list_bytes(self.languages_c2s)
        payload += sshtype.name_list_bytes(self.languages_s2c)
        payload += sshtype.boolean_bytes(self.first_kex_packet_follows)
        payload += sshtype.uint32_bytes(self.reserved)
        return sshtransport.BinaryPacket(payload=payload)

    def optimal_response(self):
        return KexInit(
            kex_algorithms=self.kex_algorithms,
            server_host_key_algorithms=self.server_host_key_algorithms,
            encryption_algorithms_c2s=self.encryption_algorithms_c2s,
            encryption_algorithms_s2c=self.encryption_algorithms_s2c,
            mac_algorithms_c2s=self.mac_algorithms_c2s,
            mac_algorithms_s2c=self.mac_algorithms_s2c,
            compression_algorithms_c2s=self.compression_algorithms_c2s,
            compression_algorithms_s2c=self.compression_algorithms_s2c,
            languages_c2s=self.languages_c2s,
            languages_s2c=self.languages_s2c
        )

class DHGEXRequest(object):
    def __init__(self, **kwargs):
        if "packet" in kwargs:
            self.__parse(kwargs["packet"].payload)
        else:
            self.min = kwargs.get("min", 1024)
            self.n   = kwargs["n"] 
            self.max = kwargs.get("max", 8192)

    def to_packet(self):
        payload = struct.pack(">BLLL", SSH_MSG_KEX_DH_GEX_REQUEST, self.min, self.n, self.max)
        return sshtransport.BinaryPacket(payload=payload)

class DHGEXGroup(object):
    def __init__(self, **kwargs):
        if "packet" in kwargs:
            self.__parse(kwargs["packet"].payload)
        else:
            self.prime     = kwargs["prime"]
            self.generator = kwargs["generator"]

    def __parse(self, payload):
        msg_type = struct.unpack(">B", payload[:1])[0]
        payload = payload[1:]

        if msg_type != SSH_MSG_KEX_DH_GEX_GROUP:
            raise Exception("SSH_MSG_KEX_DH_GEX_GROUP expected")
    
        ( payload, self.prime ) = sshtype.parse_mpint(payload)
        ( payload, self.generator ) = sshtype.parse_mpint(payload)

        if len(payload) > 0:
            print("WARNING! Extra bytes after SSH_MSG_KEXINIT.")
        
