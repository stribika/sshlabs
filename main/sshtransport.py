import binascii
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
            buf = conn.recv(64)
            if len(buf) == 0:
                break
            ident_str += buf

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

    def to_dict(self):
        return self.__dict__

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
            if len(buf) == 0:
                break
            response += buf
        return response

    def send(self, conn):
        padding_length = 8 - (5 + len(self.payload) % 8)

        if padding_length < 4:
            padding_length += 8

        padding = padding_length * b'\x00'
        header = struct.pack(">LB", len(self.payload) + padding_length + 1, padding_length)
        conn.send(header + self.payload + padding + self.mac)

    def __str__(self):
        return binascii.hexlify(self.payload).decode("ASCII")

class SSHSocket(object):
    def __init__(self, tcp_socket):
        self.__socket   = tcp_socket
        self.__id_sent  = False
        self.__id_recvd = False

    def recv_identification(self):
        self.__id_recvd = True
        return IdentificationString(recvfrom=self.__socket)

    def send_identification(self, identification_string):
        self.__id_sent = True
        identification_string.send(self.__socket)

    def recv_packet(self):
        return BinaryPacket(recvfrom=self.__socket)

    def send_packet(self, binary_packet):
        binary_packet.send(self.__socket)

    def send(self, x):
        if self.__id_sent:
            self.send_packet(x)
        else:
            self.send_identification(x)

    def recv(self):
        if self.__id_recvd:
            return self.recv_packet()
        else:
            return self.recv_identification()
