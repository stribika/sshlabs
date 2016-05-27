import sys
import unittest

sys.path.append("../main")

from algorithms import *
from sshmessage import DHGEXGroup

class TestIssues(unittest.TestCase):
    def test_kex_dh_gex_small_group(self):
        group = DHGEXGroup(prime=561, generator=2)
        issue = issue_kex_dh_gex_small_group(Severity.error, group, 10)
        # some basic asserts... the point is it didn't throw
        self.assertIsInstance(issue, Issue)
        self.assertEqual(issue.severity, Severity.error)
        self.assertEqual("Key exchange: small DH group", issue.what)

    def test_kex_dh_gex_unsafe_group(self):
        group = DHGEXGroup(prime=561, generator=2)
        issue = issue_kex_dh_gex_unsafe_group(Severity.error, group)
        self.assertIsInstance(issue, Issue)
        self.assertEqual(issue.severity, Severity.error)
        self.assertEqual("Key exchange: unsafe DH group", issue.what)

