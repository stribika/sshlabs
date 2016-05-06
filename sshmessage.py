import struct

import sshtype

SSH_MSG_KEXINIT                = 20
SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30
SSH_MSG_KEX_DH_GEX_GROUP       = 31
SSH_MSG_KEX_DH_GEX_INIT        = 32
SSH_MSG_KEX_DH_GEX_REPLY       = 33
SSH_MSG_KEX_DH_GEX_REQUEST     = 34

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
        ( payload, self.kex_algorithms ) = sshtype.parse_name_list(payload)
        ( payload, self.server_host_key_algorithms ) = sshtype.parse_name_list(payload)
        ( payload, self.encryption_algorithms_client_to_server ) = sshtype.parse_name_list(payload)
        ( payload, self.encryption_algorithms_server_to_client ) = sshtype.parse_name_list(payload)
        ( payload, self.mac_algorithms_client_to_server ) = sshtype.parse_name_list(payload)
        ( payload, self.mac_algorithms_server_to_client ) = sshtype.parse_name_list(payload)
        ( payload, self.compression_algorithms_client_to_server ) = sshtype.parse_name_list(payload)
        ( payload, self.compression_algorithms_server_to_client ) = sshtype.parse_name_list(payload)
        ( payload, self.languages_client_to_server ) = sshtype.parse_name_list(payload)
        ( payload, self.languages_server_to_client ) = sshtype.parse_name_list(payload)
        ( payload, self.first_kex_packet_follows ) = sshtype.parse_boolean(payload)
        ( payload, self.reserved ) = sshtype.parse_uint32(payload)
    
        if self.reserved != 0:
            print("WARNING! Reserved field not zero.")
        
        if len(payload) > 0:
            print("WARNING! Extra bytes after SSH_MSG_KEXINIT.")

    def get_bytes(self):
        payload = struct.pack(">B16s", SSH_MSG_KEXINIT, self.cookie)
        payload += sshtype.name_list_bytes(self.kex_algorithms)
        payload += sshtype.name_list_bytes(self.server_host_key_algorithms)
        payload += sshtype.name_list_bytes(self.encryption_algorithms_client_to_server)
        payload += sshtype.name_list_bytes(self.encryption_algorithms_server_to_client)
        payload += sshtype.name_list_bytes(self.mac_algorithms_client_to_server)
        payload += sshtype.name_list_bytes(self.mac_algorithms_server_to_client)
        payload += sshtype.name_list_bytes(self.compression_algorithms_client_to_server)
        payload += sshtype.name_list_bytes(self.compression_algorithms_server_to_client)
        payload += sshtype.name_list_bytes(self.languages_client_to_server)
        payload += sshtype.name_list_bytes(self.languages_server_to_client)
        payload += sshtype.boolean_bytes(self.first_kex_packet_follows)
        payload += sshtype.uint32_bytes(self.reserved)
        return payload

class DHGEXRequest(object):
    def __init__(self):
        self.min = None
        self.n = None
        self.max = None

    def get_bytes(self):
        return struct.pack(">BLLL", SSH_MSG_KEX_DH_GEX_REQUEST, self.min, self.n, self.max)
