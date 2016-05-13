import struct

class IdentificationString(object):
    """
    From RFC 4253

    SSH-protoversion-softwareversion SP comments CR LF
    """

    def __init__(self, **kwargs):
        if "recvfrom" in kwargs:
            self.__recv(kwargs["recvfrom"])
        else:
            self.protoversion    = kwargs["protoversion"]
            self.softwareversion = kwargs["softwareversion"]
            self.comments        = kwargs.get("comments")
    
    def __recv(self, conn):
        ident_str = b""

        while b"\n" not in ident_str:
            ident_str += conn.recv(64)

        ident_str = ident_str[:-2 if ident_str.endswith(b"\r\n") else -1]
        ident_str = ident_str.decode("ASCII").split("-", 2)

        if ident_str[0] != "SSH":
            raise Exception("invalid protocol: " + ident_str[0])

        if len(ident_str) != 3:
            raise Exception("exactly 3 dash separated parts expected in the identification string")

        self.protoversion = ident_str[1]
        version_and_comments = ident_str[2].split(" ", 2)
        self.softwareversion = version_and_comments[0]
        self.comments = version_and_comments[1] if len(version_and_comments) > 1 else None
    
    def send(self, conn):
        conn.send((str(self) + "\r\n").encode("ASCII"))

    def __str__(self):
        version_and_comments = self.softwareversion
        if self.comments:
            version_and_comments += " " + self.comments
        return "SSH-{0}-{1}".format(self.protoversion, version_and_comments)

class BinaryPacket(object):
    """
    From RFC 4253

    Each packet is in the following format:

    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    """

    def __init__(self, **kwargs):
        if "recvfrom" in kwargs:
            self.__recv(kwargs["recvfrom"], kwargs.get("maclength", 0))
        else:
            self.payload = kwargs["payload"]
            self.mac     = kwargs.get("mac", b"")

    def __recv(self, conn, mac_length):
        header = self.__recv_bytes(conn, 5)
        ( packet_length, padding_length ) = struct.unpack(">LB", header)

        if padding_length < 4:
           raise Exception("There MUST be at least four bytes of padding.")

        body_fmt = "{}s{}s{}s".format(
            packet_length - padding_length - 1,
            padding_length,
            mac_length
        )
        size = struct.calcsize(body_fmt)
        
        if size + len(header) > 35000:
            raise Exception("packet too large")
        
        body = self.__recv_bytes(conn, size)
        ( self.payload, padding, self.mac ) = struct.unpack(body_fmt, body)

    def __recv_bytes(self, conn, n):
        response = b""
        while len(response) < n:
            buf = conn.recv(n - len(response))
            response += buf
        return response

    def send(self, conn):
        padding_length = 8 - (5 + len(self.payload) % 8)

        if padding_length < 4:
            padding_length += 8

        padding = padding_length * b'\x00'
        header = struct.pack(">LB", len(self.payload) + padding_length + 1, padding_length)
        conn.send(header + self.payload + padding + self.mac)

if __name__ == '__main__':
    class FakeSocket(object):
        def __init__(self):
            self.recv_buffer = b""
            self.send_buffer = b""

        def recv(self, n):
            resp = self.recv_buffer[:n]
            self.recv_buffer = self.recv_buffer[n:]
            return resp

        def send(self, x):
            self.send_buffer += x

    def test_idstr():
        conn = FakeSocket()
        conn.recv_buffer = b"SSH-2.00-SecureMcShellface_1.0\r\n"
        idstr = IdentificationString(recvfrom=conn)
        assert idstr.protoversion == "2.00"
        assert idstr.softwareversion == "SecureMcShellface_1.0"
        idstr.send(conn)
        assert conn.send_buffer == b"SSH-2.00-SecureMcShellface_1.0\r\n"
    test_idstr()

    def test_binpkt():
        conn = FakeSocket()
        conn.recv_buffer = b"\x00\x00\x00\x14\x07Hello World!\x00\x00\x00\x00\x00\x00\x00"
        binpkt = BinaryPacket(recvfrom=conn)
        assert binpkt.payload == b"Hello World!"
        assert binpkt.mac == b""
        binpkt.send(conn)
        assert conn.send_buffer == b"\x00\x00\x00\x14\x07Hello World!\x00\x00\x00\x00\x00\x00\x00"
    test_binpkt()

