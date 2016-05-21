import enum

class Severity(enum.IntEnum):
    info     = 0 # Problem with the scanner
    notice   = 1 # Speculative weakness
    warning  = 2 # Theoretical weakness
    error    = 4 # Expensive attack
    critical = 8 # Cheap attack

class Issue(object):
    def __init__(self, severity, what, *args):
        self.severity = severity
        self.what     = what
        self.args     = args

    def __str__(self):
        return "{0}! {1}: {2}".format(
            self.severity.name.upper(),
            self.what,
            ", ".join([ str(arg) for arg in self.args ])
        )

class CipherMode(enum.IntEnum):
    CBC    = 0
    STREAM = 1 # or CTR
    AEAD   = 2

class Cipher(object):
    def __init__(self, mode, *args):
        self.mode = mode
        self.issues = args

class MACMode(enum.IntEnum):
    EAM = 0
    ETM = 1

class MAC(object):
    def __init__(self, mode, *args):
        self.mode = mode
        self.issues = args

known_kex_algorithms = {
    "curve25519-sha256@libssh.org": [],
    "diffie-hellman-group1-sha1": [
        Issue(Severity.error,   "small DH group", "1024 bits", "diffie-hellman-group1-sha1"),
        Issue(Severity.warning, "weak key exchange hash", "diffie-hellman-group1-sha1" ),
    ],
    "diffie-hellman-group14-sha1": [
        Issue(Severity.warning, "weak key exchange hash", "diffie-hellman-group14-sha1")
    ],
    "diffie-hellman-group14-sha256": [],
    "diffie-hellman-group15-sha256": [],
    "diffie-hellman-group16-sha256": [],
    "diffie-hellman-group-exchange-sha1": [
        Issue(Severity.warning, "weak key exchange hash", "diffie-hellman-group-exchange-sha1" )
    ],
    "diffie-hellman-group-exchange-sha256": [],
    "ecdh-sha2-nistp256": [
        Issue(Severity.notice, "unsafe elliptic curve", "ecdh-sha2-nistp256")
    ],
    "ecdh-sha2-nistp384": [
        Issue(Severity.notice, "unsafe elliptic curve", "ecdh-sha2-nistp384")
    ],
    "ecdh-sha2-nistp521": [],
}

known_ciphers = {
    "3des-cbc": Cipher(CipherMode.CBC,
        Issue(Severity.warning, "small cipher block size", "3des-cbc")),
    "aes128-cbc": Cipher(CipherMode.CBC),
    "aes192-cbc": Cipher(CipherMode.CBC),
    "aes256-cbc": Cipher(CipherMode.CBC),
    "aes128-ctr": Cipher(CipherMode.STREAM),
    "aes192-ctr": Cipher(CipherMode.STREAM),
    "aes256-ctr": Cipher(CipherMode.STREAM),
    "aes128-gcm@openssh.com": Cipher(CipherMode.AEAD),
    "aes256-gcm@openssh.com": Cipher(CipherMode.AEAD),
    "arcfour": Cipher(CipherMode.STREAM,
        Issue(Severity.error, "weak cipher algorithm", "arcfour")),
    "arcfour128": Cipher(CipherMode.STREAM,
        Issue(Severity.error, "weak cipher algorithm", "arcfour128")),
    "arcfour256": Cipher(CipherMode.STREAM,
        Issue(Severity.error, "weak cipher algorithm", "arcfour256")),
    "blowfish-cbc": Cipher(CipherMode.CBC,
        Issue(Severity.warning, "small cipher block size", "blowfish-cbc")),
    "cast128-cbc": Cipher(CipherMode.CBC,
        Issue(Severity.warning, "small cipher block size", "cast128-cbc")),
    "chacha20-poly1305@openssh.com": Cipher(CipherMode.AEAD),
}

known_macs = {
    "hmac-md5": MAC(MACMode.EAM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-md5")),
    "hmac-md5-96": MAC(MACMode.EAM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-md5-96"),
        Issue(Severity.notice, "small MAC tag", "96 bits", "hmac-md5-96")),
    "hmac-ripemd160": MAC(MACMode.EAM),
    "hmac-sha1": MAC(MACMode.EAM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-sha1")),
    "hmac-sha1-96": MAC(MACMode.EAM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-sha1-96"),
        Issue(Severity.notice, "small MAC tag", "96 bits", "hmac-sha1-96")),
    "hmac-sha2-256": MAC(MACMode.EAM),
    "hmac-sha2-512": MAC(MACMode.EAM),
    "umac-64@openssh.com": MAC(MACMode.EAM,
        Issue(Severity.notice, "small MAC tag", "64 bits", "umac-64@openssh.com")),
    "umac-128@openssh.com": MAC(MACMode.EAM),
    "hmac-md5-etm@openssh.com": MAC(MACMode.ETM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-md5-etm@openssh.com")),
    "hmac-md5-96-etm@openssh.com": MAC(MACMode.ETM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-md5-96-etm@openssh.com"),
        Issue(Severity.notice, "small MAC tag", "96 bits", "hmac-md5-96-etm@openssh.com")),
    "hmac-ripemd160-etm@openssh.com": MAC(MACMode.ETM),
    "hmac-sha1-etm@openssh.com": MAC(MACMode.ETM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-sha1-etm@openssh.com")),
    "hmac-sha1-96-etm@openssh.com": MAC(MACMode.ETM,
        Issue(Severity.notice, "weak HMAC hash", "hmac-sha1-96-etm@openssh.com"),
        Issue(Severity.notice, "small MAC tag", "96 bits", "hmac-sha1-96-etm@openssh.com")),
    "hmac-sha2-256-etm@openssh.com": MAC(MACMode.ETM),
    "hmac-sha2-512-etm@openssh.com": MAC(MACMode.ETM),
    "umac-64-etm@openssh.com": MAC(MACMode.ETM,
        Issue(Severity.notice, "small MAC tag", "64 bits", "umac-64-etm@openssh.com")),
    "umac-128-etm@openssh.com": MAC(MACMode.ETM),
}
