import sys
import unittest

sys.path.append("../main")

from sshtype import *

class TestUInt32(unittest.TestCase):
    def test_from_bytes(self):
        uint32 = UInt32()
        self.assertEqual(uint32.from_bytes(b"\x00\x00\x01\x02"), (b"", 0x102))

    def test_to_bytes(self):
        uint32 = UInt32()
        self.assertEqual(uint32.to_bytes(0x10203), b"\x00\x01\x02\x03")
