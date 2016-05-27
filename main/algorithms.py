import enum

class Severity(enum.IntEnum):
    info     = 0 # Problem with the scanner
    notice   = 1 # Speculative weakness
    warning  = 2 # Theoretical weakness
    error    = 4 # Expensive attack
    critical = 8 # Cheap attack

class Issue(object):
    def __init__(self, severity, what, details=None, instructions=None):
        self.severity     = severity
        self.what         = what
        self.details      = details
        self.instructions = instructions

    def __str__(self):
        return "{0}! {1}".format(self.severity.name.upper(), self.what)

    def to_dict(self):
        return self.__dict__

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

def issue_unknown(algo_type, algo_name):
    return Issue(
Severity.info,
"Unknown {0} algorithm: {1}".format(algo_type, algo_name),
"""The SSHLabs Scanner does not know anything about {0} algorithm {1}. It could
be perfectly safe. Or not.""",
"""No action required. If you know what this algorithm is, consider sending a
pull request to https://github.com/stribika/sshlabs."""
    )

def issue_kex_dh_small_group(severity, algo, size):
    return Issue(
severity,
"Key exchange: small DH group",
"""The security of the Diffie-Hellman key exchange relies on the difficulty of
the discrete logarithm problem. The server is configured to use {0}, which uses
a prime modulus too small (only {1} bits) to provide forward secrecy.""".format(algo, size),
"""Remove {0} from the KexAlgorithms line in /etc/ssh/sshd_config, then send
SIGHUP to sshd.""".format(algo)
    )

def issue_kex_weak_hash(severity, algo):
    return Issue(
severity,
"Key exchange: weak hash",
"""The downgrade resistance of the SSH protocol relies on using a collision
resistant hash function for deriving the symmetric keys from the shared secret
established during the key exchange. The server is configured to use {0}, which
uses a weak hash function, that does not provide downgrade resistance.""".format(algo),
"""Remove {0} from the KexAlgorithms line in /etc/ssh/sshd_config, then send
SIGHUP to sshd.""".format(algo)
    )

def issue_kex_dh_gex_small_group(severity, group, size):
    return Issue(
severity,
"Key exchange: small DH group",
"""The security of the Diffie-Hellman key exchange relies on the difficulty of
the discrete logarithm problem. The server is configured to use Diffie-Hellman
group exchange, and uses a prime modulus too small (only {0} bits) to provide
forward secrecy.""".format(size),
"""Remove the line with prime modulus {0:x} and generator {1:x} from
/etc/ssh/moduli with the following commands:

awk '$5 > 2000' /etc/ssh/moduli > "${{HOME}}/moduli"
wc -l "${{HOME}}/moduli" # make sure there is something left
mv "${{HOME}}/moduli" /etc/ssh/moduli

It is possible that the moduli file does not exist, or contains no safe groups.
In this case, regenerate it with the following commands:

ssh-keygen -G /etc/ssh/moduli.all -b 4096
ssh-keygen -T /etc/ssh/moduli.safe -f /etc/ssh/moduli.all
mv /etc/ssh/moduli.safe /etc/ssh/moduli
rm /etc/ssh/moduli.all""".format(group.prime, group.generator)
    )

def issue_kex_dh_gex_unsafe_group(severity, group):
    return Issue(
severity,
"Key exchange: unsafe DH group",
"""The security of the Diffie-Hellman key exchange relies on the difficulty of
the discrete logarithm problem. If the modulus is not a safe prime, it may be
possible to solve DLP in polynomial time.""",
"""Remove the line with prime modulus {0:x} and generator {1:x} from
/etc/ssh/moduli. It is possible that the moduli file does not exist, or contains
no safe groups. In this case, regenerate it with the following commands:

ssh-keygen -G /etc/ssh/moduli.all -b 4096
ssh-keygen -T /etc/ssh/moduli.safe -f /etc/ssh/moduli.all
mv /etc/ssh/moduli.safe /etc/ssh/moduli
rm /etc/ssh/moduli.all""".format(group.prime, group.generator)
    )

def issue_kex_ecdh_unsafe_curve(severity, algo):
    return Issue(
severity,
"Key exchange: unsafe elliptic curve",
"""The elliptic curve used by {0} does not meet the SafeCurves criteria. This
means they are unnecessarily difficult to implement safely.""".format(algo),
"""Remove {0} from the KexAlgorithms line in /etc/ssh/sshd_config, then send
SIGHUP to sshd.""".format(algo)
    )

def issue_sign_dsa(severity, algo):
    return Issue(
severity,
"Signature: requires per-signature entropy",
"""The {0} host key algorithm requires entropy for each signature, and leaks the
secret key if the random values are predictable or reused even once.""".format(algo),
"""Delete the {0} host key files from /etc/ssh, and the HostKey line from
/etc/ssh/sshd_config referring to these files. If there are no HostKey lines at
all, add the key files you wish to use.""".format(algo)
    )

def issue_sign_ecdsa_unsafe_curve(severity, algo):
    return Issue(
severity,
"Signature: unsafe elliptic curve",
"""The elliptic curve used by {0} does not meet the SafeCurves criteria. This
means they are unnecessarily difficult to implement safely.""".format(algo),
"""Delete the {0} host key files from /etc/ssh, and the HostKey line from
/etc/ssh/sshd_config referring to these files. If there are no HostKey lines at
all, add the key files you wish to use.""".format(algo)
    )

def issue_sign_small_key(severity, algo, size):
    return Issue(
severity,
"Signature: small key size",
"""The host key used by {0} is only {1} bits, small enough to be
bruteforced.""".format(algo, size),
"""Delete the {0} host key files from /etc/ssh, then if larger keys are
supported, create them with ssh-keygen. Otherwise remove the HostKey line from
/etc/ssh/sshd_config referring to these files. If there are no HostKey lines at
all, add the key files you wish to use.""".format(algo)
    )

def issue_cipher_small_block(severity, algo, size):
    return Issue(
severity,
"Cipher: small block size",
"""The block size of the {0} cipher is only {1} bits. Repeated ciphertext blocks
leak information about the plaintext.""".format(algo, size),
"""Remove {0} from the Ciphers line in /etc/ssh/sshd_config, then send SIGHUP to
sshd.""".format(algo)
    )

def issue_cipher_weak(severity, algo):
    return Issue(
severity,
"Cipher: weak algorithm",
"""The {0} cipher algorithm is known to be broken.""".format(algo),
"""Remove {0} from the Ciphers line in /etc/ssh/sshd_config, then send SIGHUP to
sshd.""".format(algo)
    )

def issue_authencr_cbc_and_mac(severity, cipher, mac):
    return Issue(
severity,
"Authenticated encryption: CBC-and-MAC",
"""The correct way to build authenticated encryption from a cipher and a MAC
is to encrypt, then append the MAC of the ciphertext. The server is configured
to encrypt with {0}, and append the {1} of the plaintext. Using a cipher in CBC
mode might lead to padding oracle attacks if implemented incorrectly.""".format(cipher, mac),
"""Remove {0} from the Ciphers line, or remove {1} from the MACs line in
/etc/sshd_config, then send SIGHUP to sshd.""".format(cipher, mac),
    )

KEX_DH_GEX_SHA1            = "diffie-hellman-group-exchange-sha1"
KEX_DH_GEX_SHA256          = "diffie-hellman-group-exchange-sha256"
KEX_DH_GROUP1_SHA1         = "diffie-hellman-group1-sha1"
KEX_DH_GROUP14_SHA1        = "diffie-hellman-group14-sha1"
KEX_DH_GROUP14_SHA256      = "diffie-hellman-group14-sha256"
KEX_DH_GROUP15_SHA256      = "diffie-hellman-group15-sha256"
KEX_DH_GROUP16_SHA256      = "diffie-hellman-group16-sha256"
KEX_ECDH_CURVE25519_SHA256 = "curve25519-sha256@libssh.org"
KEX_ECDH_NISTP256_SHA256   = "ecdh-sha2-nistp256"
KEX_ECDH_NISTP384_SHA384   = "ecdh-sha2-nistp384"
KEX_ECDH_NISTP521_SHA512   = "ecdh-sha2-nistp521"

known_kex_algorithms = {
    KEX_ECDH_CURVE25519_SHA256: [],
    KEX_DH_GROUP1_SHA1: [
        issue_kex_dh_small_group(Severity.error, KEX_DH_GROUP1_SHA1, 1024),
        issue_kex_weak_hash(Severity.warning, KEX_DH_GROUP1_SHA1),
    ],
    KEX_DH_GROUP14_SHA1: [
        issue_kex_weak_hash(Severity.warning, KEX_DH_GROUP14_SHA1),
    ],
    KEX_DH_GROUP14_SHA256: [],
    KEX_DH_GROUP15_SHA256: [],
    KEX_DH_GROUP16_SHA256: [],
    KEX_DH_GEX_SHA1: [
        issue_kex_weak_hash(Severity.warning, KEX_DH_GEX_SHA1),
    ],
    KEX_DH_GEX_SHA256: [],
    KEX_ECDH_NISTP256_SHA256: [
        issue_kex_ecdh_unsafe_curve(Severity.notice, KEX_ECDH_NISTP256_SHA256)
    ],
    KEX_ECDH_NISTP384_SHA384: [
        issue_kex_ecdh_unsafe_curve(Severity.notice, KEX_ECDH_NISTP384_SHA384)
    ],
    KEX_ECDH_NISTP521_SHA512: [],
}

known_ciphers = {
    "3des-cbc": Cipher(CipherMode.CBC,
        issue_cipher_small_block(Severity.warning, "3des-cbc", 64)),
    "aes128-cbc": Cipher(CipherMode.CBC),
    "aes192-cbc": Cipher(CipherMode.CBC),
    "aes256-cbc": Cipher(CipherMode.CBC),
    "aes128-ctr": Cipher(CipherMode.STREAM),
    "aes192-ctr": Cipher(CipherMode.STREAM),
    "aes256-ctr": Cipher(CipherMode.STREAM),
    "aes128-gcm@openssh.com": Cipher(CipherMode.AEAD),
    "aes256-gcm@openssh.com": Cipher(CipherMode.AEAD),
    "arcfour": Cipher(CipherMode.STREAM,
        issue_cipher_weak(Severity.error, "arcfour")),
    "arcfour128": Cipher(CipherMode.STREAM,
        issue_cipher_weak(Severity.error, "arcfour128")),
    "arcfour256": Cipher(CipherMode.STREAM,
        issue_cipher_weak(Severity.error, "arcfour256")),
    "blowfish-cbc": Cipher(CipherMode.CBC,
        issue_cipher_small_block(Severity.warning, "blowfish-cbc", 64)),
    "cast128-cbc": Cipher(CipherMode.CBC,
        issue_cipher_small_block(Severity.warning, "cast128-cbc", 64)),
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

SIGN_DSA                   = "ssh-dss"
SIGN_ECDSA_NISTP256_SHA256 = "ecdsa-sha2-nistp256"
SIGN_ECDSA_NISTP384_SHA384 = "ecdsa-sha2-nistp384"
SIGN_ECDSA_NISTP521_SHA512 = "ecdsa-sha2-nistp521"
SIGN_RSA_SHA1              = "ssh-rsa"
SIGN_RSA_SHA256            = "rsa-sha2-256"
SIGN_RSA_SHA512            = "rsa-sha2-512"

known_host_key_algorithms = {
    SIGN_DSA: [
        issue_sign_dsa(Severity.notice, SIGN_DSA),
        issue_sign_small_key(Severity.error, SIGN_DSA, 1024) 
    ],
    SIGN_ECDSA_NISTP256_SHA256: [
        issue_sign_dsa(Severity.notice, SIGN_ECDSA_NISTP256_SHA256),
        issue_sign_ecdsa_unsafe_curve(Severity.notice, SIGN_ECDSA_NISTP256_SHA256),
    ],
    SIGN_ECDSA_NISTP384_SHA384: [
        issue_sign_dsa(Severity.notice, SIGN_ECDSA_NISTP384_SHA384),
        issue_sign_ecdsa_unsafe_curve(Severity.notice, SIGN_ECDSA_NISTP256_SHA256),
    ],
    SIGN_ECDSA_NISTP521_SHA512: [
        issue_sign_dsa(Severity.notice, SIGN_ECDSA_NISTP521_SHA512),
    ],
    SIGN_RSA_SHA1: [],
    SIGN_RSA_SHA256: [],
    SIGN_RSA_SHA512: [],
}


