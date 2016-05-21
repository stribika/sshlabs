import sys
import unittest

sys.path.append("../main")

from sshtransport import *

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

class TestIdentificationString(unittest.TestCase):
    def test_recv(self):        
        conn = FakeSocket()
        conn.recv_buffer = b"SSH-2.00-SecureMcShellface_1.0\r\n"
        idstr = IdentificationString(recvfrom=conn)
        self.assertEqual(idstr.protoversion, "2.00")
        self.assertEqual(idstr.softwareversion, "SecureMcShellface_1.0")

    def test_send(self):
        conn = FakeSocket()
        idstr = IdentificationString(protoversion="2.00", softwareversion="SecureMcShellface_1.0")
        idstr.send(conn)
        self.assertEqual(conn.send_buffer, b"SSH-2.00-SecureMcShellface_1.0\r\n")

class TestBinaryPacket(unittest.TestCase):
    def test_recv(self):
        conn = FakeSocket()
        conn.recv_buffer = b"\x00\x00\x00\x14\x07Hello World!\x00\x00\x00\x00\x00\x00\x00"
        binpkt = BinaryPacket(recvfrom=conn)
        self.assertEqual(binpkt.payload, b"Hello World!")
        self.assertEqual(binpkt.mac, b"")

    def test_send(self):
        conn = FakeSocket()
        binpkt = BinaryPacket(payload=b"Hello World!")
        binpkt.send(conn)
        self.assertEqual(conn.send_buffer, b"\x00\x00\x00\x14\x07Hello World!\x00\x00\x00\x00\x00\x00\x00")
