import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.append("../main")

from algorithms import *

port = 2222

def sshd(**kwargs):
    dirname  = tempfile.mkdtemp()
    confname = dirname + "/sshd_config"
    logname  = dirname + "/sshd.log"

    with open(confname, "w") as conf:
        print("LogLevel", "DEBUG3", file=conf)
        print("ListenAddress", "127.0.0.1:2222", file=conf)

        for key, value in kwargs.items():
            if type(value) == str:
                print(key, value.replace("${confdir}", dirname), file=conf)
            else:
                for val in value:
                    print(key, val.replace("${confdir}", dirname), file=conf)

        for f in os.listdir("./config"):
            shutil.copy("./config/" + f, dirname)

            if f.startswith("ssh_host_") and f.endswith("_key") and "HostKey" not in kwargs:
                print("HostKey", dirname + "/" + f, file=conf)

    return subprocess.Popen([
        "/usr/sbin/sshd",
        "-f", confname,
        "-E", logname,
        "-D",
    ])

def scan(*args):
    scanner = subprocess.Popen(
        [ "../main/scanner.py", "--json" ] + [ "--" + arg for arg in args ] + [ "127.0.0.1:2222" ],
        stdout=subprocess.PIPE
    )
    ( stdout, stderr ) = scanner.communicate()

    if scanner.returncode == 0:
        return json.loads(stdout.decode())
    else:
        return None

def what(result):
    return [ issue["what"] for issue in result["issues"] ]

class TestScanner(unittest.TestCase):
    def tearDown(self): 
        self.sshd.terminate()

    def test_djb(self):
        self.sshd = sshd(
            KexAlgorithms=KEX_ECDH_CURVE25519_SHA256,
            HostKey="${confdir}/ssh_host_ed25519_key",
            Ciphers="chacha20-poly1305@openssh.com"
        )
        results = scan("algorithms")
        self.assertEqual(len(results), 1)

        for r in results:
            self.assertEqual(r["host"], "127.0.0.1")
            self.assertEqual(r["port"], 2222)
            self.assertEqual(r["kex_init"]["kex_algorithms"], [ KEX_ECDH_CURVE25519_SHA256 ])
            self.assertEqual(r["kex_init"]["server_host_key_algorithms"], [ "ssh-ed25519" ])
            self.assertEqual(r["kex_init"]["encryption_algorithms_c2s"], [ "chacha20-poly1305@openssh.com" ])
            self.assertEqual(r["kex_init"]["encryption_algorithms_s2c"], [ "chacha20-poly1305@openssh.com" ])

    def test_nsa(self):
        self.sshd = sshd(
            KexAlgorithms=",".join([
                KEX_ECDH_NISTP521_SHA512,
                KEX_ECDH_NISTP384_SHA384,
                KEX_ECDH_NISTP256_SHA256,
            ]),
            HostKey=[
                "${confdir}/ssh_host_ecdsa521_key",
                "${confdir}/ssh_host_ecdsa384_key",
                "${confdir}/ssh_host_ecdsa256_key",
            ],
            Ciphers="aes256-gcm@openssh.com,aes128-gcm@openssh.com"
        )
        results = scan("algorithms", "details")
        self.assertEqual(len(results), 1)

        for r in results:
            self.assertEqual(r["host"], "127.0.0.1")
            self.assertEqual(r["port"], 2222)
            self.assertEqual(
                r["kex_init"]["kex_algorithms"],
                [ KEX_ECDH_NISTP521_SHA512, KEX_ECDH_NISTP384_SHA384, KEX_ECDH_NISTP256_SHA256 ]
            )
            self.assertEqual(
                r["kex_init"]["server_host_key_algorithms"],
                [SIGN_ECDSA_NISTP521_SHA512,SIGN_ECDSA_NISTP384_SHA384,SIGN_ECDSA_NISTP256_SHA256]
            )
            self.assertEqual(
                r["kex_init"]["encryption_algorithms_c2s"],
                [ "aes256-gcm@openssh.com", "aes128-gcm@openssh.com" ]
            )
            self.assertEqual(
                r["kex_init"]["encryption_algorithms_s2c"],
                [ "aes256-gcm@openssh.com", "aes128-gcm@openssh.com" ]
            )
            self.assertTrue(any([ x == "Key exchange: unsafe elliptic curve" for x in what(r) ]))
            self.assertTrue(any([ x == "Signature: requires per-signature entropy" for x in what(r) ]))
            self.assertTrue(any([ x == "Signature: unsafe elliptic curve" for x in what(r) ]))

    def test_old(self):
        self.sshd = sshd(
            KexAlgorithms=",".join([ KEX_DH_GROUP1_SHA1, KEX_DH_GROUP14_SHA1 ]),
            HostKey=[ "${confdir}/ssh_host_rsa1024_key", "${confdir}/ssh_host_dsa_key" ],
            HostKeyAlgorithms="ssh-rsa,ssh-dss",
            Ciphers="3des-cbc,arcfour",
            MACs="hmac-md5"
        )
        results = scan("algorithms", "instructions")
        self.assertEqual(len(results), 1)

        for r in results:
            self.assertEqual(r["host"], "127.0.0.1")
            self.assertEqual(r["port"], 2222)
            self.assertEqual(
                r["kex_init"]["kex_algorithms"],
                [ KEX_DH_GROUP1_SHA1, KEX_DH_GROUP14_SHA1 ]
            )
            self.assertEqual(
                r["kex_init"]["server_host_key_algorithms"],
                [ SIGN_RSA_SHA1, SIGN_RSA_SHA512, SIGN_RSA_SHA256, SIGN_DSA ]
            )
            self.assertEqual(r["kex_init"]["encryption_algorithms_c2s"], [ "3des-cbc","arcfour" ])
            self.assertEqual(r["kex_init"]["encryption_algorithms_s2c"], [ "3des-cbc","arcfour" ])
            self.assertEqual(r["kex_init"]["mac_algorithms_c2s"], [ "hmac-md5" ])
            self.assertEqual(r["kex_init"]["mac_algorithms_s2c"], [ "hmac-md5" ])
            self.assertTrue(any([ x == "Key exchange: weak hash" for x in what(r) ]))
            self.assertTrue(any([ x == "Key exchange: small DH group" for x in what(r) ]))
            self.assertTrue(any([ x == "Signature: small key size" for x in what(r) ]))
            self.assertTrue(any([ x == "Signature: requires per-signature entropy" for x in what(r) ]))
            self.assertTrue(any([ x == "Cipher: small block size" for x in what(r) ]))
            self.assertTrue(any([ x == "Authenticated encryption: CBC-and-MAC" for x in what(r) ]))

    def test_classic(self):
        self.sshd = sshd(
            KexAlgorithms=",".join([ KEX_DH_GEX_SHA256 ]),
            HostKey=[ "${confdir}/ssh_host_rsa2048_key" ],
            Ciphers="aes256-ctr,aes192-ctr,aes128-ctr",
            MACs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com"
        )
        results = scan("algorithms", "details", "fast", "instructions")
        self.assertEqual(len(results), 1)

        for r in results:
            self.assertEqual(r["host"], "127.0.0.1")
            self.assertEqual(r["port"], 2222)
            self.assertEqual(r["kex_init"]["kex_algorithms"], [ KEX_DH_GEX_SHA256 ])
            self.assertEqual(
                r["kex_init"]["server_host_key_algorithms"],
                [ SIGN_RSA_SHA1, SIGN_RSA_SHA512, SIGN_RSA_SHA256 ]
            )
            self.assertEqual(
                r["kex_init"]["encryption_algorithms_c2s"],
                [ "aes256-ctr", "aes192-ctr", "aes128-ctr" ]
            )
            self.assertEqual(
                r["kex_init"]["encryption_algorithms_s2c"],
                [ "aes256-ctr", "aes192-ctr", "aes128-ctr" ]
            )
            self.assertEqual(
                r["kex_init"]["mac_algorithms_c2s"],
                [
                    "hmac-sha2-512-etm@openssh.com",
                    "hmac-sha2-256-etm@openssh.com",
                    "hmac-ripemd160-etm@openssh.com",
                    "umac-128-etm@openssh.com",
                ]
            )
            self.assertEqual(
                r["kex_init"]["mac_algorithms_s2c"],
                [
                    "hmac-sha2-512-etm@openssh.com",
                    "hmac-sha2-256-etm@openssh.com",
                    "hmac-ripemd160-etm@openssh.com",
                    "umac-128-etm@openssh.com",
                ]
            )


