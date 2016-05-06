import struct

def parse_string(buf):
    ( buf, length ) = parse_uint32(buf)
    return ( buf[length:], buf[:length] )

def parse_mpint(buf):
    ( buf, mpint ) = parse_string(buf)
    value = 0
    for b in mpint:
        value <<= 8
        value += b
    return ( buf, value )

def parse_name_list(buf):
    ( buf, string ) = parse_string(buf)
    return ( buf, string.decode("ASCII").split(",") )

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
