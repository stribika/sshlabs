import struct

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
