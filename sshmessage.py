"""
This might look like an SSH protocol implementation. IT IS NOT. It's not even
remotely secure. Nothing is verified, nothing is random. DO NOT USE.
"""

import struct

from sshtransport import BinaryPacket
from sshtype import *

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

class SSHMessage(object):
    def __init__(self, message_type, *args, **kwargs):
        object.__setattr__(self, "_SSHMessage__message_type", message_type)
        object.__setattr__(self, "_SSHMessage__structure",    args)
        object.__setattr__(self, "_SSHMessage__values",       {})

        for arg in args:
            self.__values[arg.name] = arg.default

        if "packet" in kwargs:
            self.from_packet(kwargs["packet"])
        else:
            kwargs_set = set(kwargs)
            valid_set = set([ s.name for s in self.__structure ])
            
            if not kwargs_set.issubset(valid_set):
                raise TypeError(
                    "unexpected arguments: " + ", ".join(kwargs_set.difference(valid_set))
                )

            self.__values.update(kwargs)

    def __getattr__(self, name):
        if name in self.__values:
            return self.__values[name]
        else:
            raise AttributeError("'{0}' object has no attribute '{1}'".format(
                type(self).__name__,
                name
            ))

    def __setattr__(self, name, value):
        if name in self.__values:
            self.__values[name] = value
        else:
            raise AttributeError("'{0}' object has no attribute '{1}'".format(
                type(self).__name__,
                name
            ))

    def __eq__(self, value):
        return type(self) == type(value) and self.__values == value.__values

    def __hash__(self):
        return hash(( type(self), frozenset(self.__values.items()) ))

    def __str__(self):
        return "{0}({1})".format(
            type(self).__name__,
            ", ".join([ s.name + "=" + s.to_str(self.__values[s.name]) for s in self.__structure ])
        )

    def from_packet(self, packet):
        data = packet.payload

        if data[0] != self.__message_type:
            raise RuntimeError("invalid type {0}, expected {1}".format(
                data[0],
                self.__message_type
            ))

        data = data[1:]

        for s in self.__structure:
            ( data, value ) = s.from_bytes(data)
            self.__values[s.name] = value

    def to_packet(self):
        data = bytes([ self.__message_type ])

        for s in self.__structure:
            data += s.to_bytes(self.__values[s.name])

        return BinaryPacket(payload=data)

class KexInit(SSHMessage):
    def __init__(self, **kwargs):
        super(type(self), self).__init__(
            SSH_MSG_KEXINIT,
            Bytes(16, "cookie", b"\x00" * 16),
            NameList("kex_algorithms", []),
            NameList("server_host_key_algorithms", []),
            NameList("encryption_algorithms_c2s", []),
            NameList("encryption_algorithms_s2c", []),
            NameList("mac_algorithms_c2s", []),
            NameList("mac_algorithms_s2c", []),
            NameList("compression_algorithms_c2s", []),
            NameList("compression_algorithms_s2c", []),
            NameList("languages_c2s", []),
            NameList("languages_s2c", []),
            Boolean("first_kex_packet_follows", False),
            UInt32("reserved", 0),
            **kwargs
        )

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

    def __str__(self):
        def strlist(name, value):
            return name + ": " + ", ".join(value)
        return "\n".join([
            strlist("Key exchange algorithms", self.kex_algorithms),
            strlist("Host key algorithms", self.server_host_key_algorithms),
            strlist("Encryption algorithms (client to server)", self.encryption_algorithms_c2s),
            strlist("Encryption algorithms (server to client)", self.encryption_algorithms_s2c),
            strlist("MAC algorithms (client to server)", self.mac_algorithms_c2s),
            strlist("MAC algorithms (server to client)", self.mac_algorithms_s2c),
        ])

class DHGEXRequest(SSHMessage):
    def __init__(self, **kwargs):
        super(type(self), self).__init__(
            SSH_MSG_KEX_DH_GEX_REQUEST,
            UInt32("min", 1024),
            UInt32("n"),
            UInt32("max", 8192),
            **kwargs
        )

class DHGEXGroup(SSHMessage):
    def __init__(self, **kwargs):
        super(type(self), self).__init__(
            SSH_MSG_KEX_DH_GEX_GROUP,
            MPInt("prime"),
            MPInt("generator"),
            **kwargs
        )

class DHGEXInit(SSHMessage):
    def __init__(self, **kwargs):
        super(type(self), self).__init__(SSH_MSG_KEX_DH_GEX_INIT, MPInt("e"), **kwargs)

class DHGEXReply(SSHMessage):
    def __init__(self, **kwargs):
        super(type(self), self).__init__(
            SSH_MSG_KEX_DH_GEX_REPLY,
            String("server_public_key"),
            MPInt("f"),
            String("signature"),
            **kwargs
        )
