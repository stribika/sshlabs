import struct

class Bytes(object):
    def __init__(self, length, name=None, default=None):
        self.name    = name
        self.default = default
        self.length  = length
    def from_bytes(self, data):
        return ( data[self.length:], data[:self.length] )
    def to_bytes(self, value):
        return value

class UInt32(object):
    def __init__(self, name=None, default=None):
        self.name    = name
        self.default = default
    def from_bytes(self, data):
        return ( data[4:], struct.unpack(">L", data[:4])[0] )
    def to_bytes(self, value):
        return struct.pack(">L", value)

if __name__ == "__main__":
    def test_uint32():
        uint32 = UInt32()
        assert (b"", 0x102) == uint32.from_bytes(b"\x00\x00\x01\x02")
        assert b"\x00\x01\x02\x03" == uint32.to_bytes(0x10203)
    test_uint32()

class String(object):
    def __init__(self, name=None, default=None):
        self.name    = name
        self.default = default
    def from_bytes(self, data):
        ( data, length ) = UInt32().from_bytes(data)
        return ( data[length:], data[:length] )
    def to_bytes(self, value):
        return UInt32().to_bytes(len(value)) + value

class MPInt(object):
    def __init__(self, name=None, default=None):
        self.name    = name
        self.default = default
    def from_bytes(self, data):
        ( data, mpint ) = String().from_bytes(data)
        value = 0
        for b in mpint:
            value <<= 8
            value += b
        # negative number
        if mpint[0] & 0x80:
            value = ~value + 1
        return ( data, value )
    def to_bytes(self, value):
        data = b""
        if value <= 0:
            data += value & 0xff
            value >>=8
        while value != 0 and value != -1:
            data += bytes([value & 0xff])
            value >>= 8
        data = data[::-1]
        # prepend zero to positive numbers if needed
        if value == 0 and (data[0] & 0x80):
            data = b"\x00" + data
        return String().to_bytes(data)

class NameList(object):
    def __init__(self, name=None, default=None):
        self.name    = name
        self.default = default
    def from_bytes(self, data):
        ( data, string ) = String().from_bytes(data)
        return ( data, string.decode("ASCII").split(",") )
    def to_bytes(self, value):
        return String().to_bytes(",".join(value).encode("ASCII"))

class Boolean(object):
    def __init__(self, name=None, default=None):
        self.name    = name
        self.default = default
    def from_bytes(self, data):
        return ( data[1:], data[0] != 0 )
    def to_bytes(self, value):
        return b'\x01' if value else b'\x00'
