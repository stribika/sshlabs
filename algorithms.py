class WARN(object):
    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.only_with = kwargs.get('only_with')

WEAK_CIPHER      = WARN('Weak cipher')
WEAK_HASH        = WARN('Weak hash')
SMALL_MODULUS    = WARN('Small modulus')
SMALL_KEY_SIZE   = WARN('Small key size')
SMALL_TAG_SIZE   = WARN('Small tag size')
SMALL_BLOCK_SIZE = WARN('Small block size')
UNSAFE_CURVE     = WARN('Elliptic curve does not meet SafeCurves requirements')
RANDOM_SIGNATURE = WARN('A weak RNG could reveal your secret key')
CBC_MODE         = WARN('CBC mode', only_with='Encrypt-and-MAC')
ENCRYPT_AND_MAC  = WARN('Encrypt-and-MAC', only_with='CBC mode')
PLAINTEXT        = WARN('Holy shit, plaintext')

KEX_ALGORITHMS = {
    'curve25519-sha256@libssh.org':         None,
    'diffie-hellman-group-exchange-sha256': None,

    'diffie-hellman-group-exchange-sha1': WEAK_HASH,
    'diffie-hellman-group14-sha1':        WEAK_HASH,
    'ecdh-sha2-nistp521':                 UNSAFE_CURVE,
    'ecdh-sha2-nistp384':                 UNSAFE_CURVE,
    'ecdh-sha2-nistp256':                 UNSAFE_CURVE,
    'diffie-hellman-group1-sha1':         [ SMALL_MODULUS, WEAK_HASH ],
}

HOST_KEY_ALGORITHMS = {
    'ssh-ed25519-cert-v01@openssh.com': None,
    'ssh-rsa-cert-v01@openssh.com':     None,
    'ssh-rsa-cert-v00@openssh.com':     None,
    'ssh-ed25519':                      None,
    'ssh-rsa':                          None,
 
    'ecdsa-sha2-nistp521-cert-v01@openssh.com': [ RANDOM_SIGNATURE, UNSAFE_CURVE ],
    'ecdsa-sha2-nistp384-cert-v01@openssh.com': [ RANDOM_SIGNATURE, UNSAFE_CURVE ],
    'ecdsa-sha2-nistp256-cert-v01@openssh.com': [ RANDOM_SIGNATURE, UNSAFE_CURVE ],
    'ecdsa-sha2-nistp521':                      [ RANDOM_SIGNATURE, UNSAFE_CURVE ],
    'ecdsa-sha2-nistp384':                      [ RANDOM_SIGNATURE, UNSAFE_CURVE ],
    'ecdsa-sha2-nistp256':                      [ RANDOM_SIGNATURE, UNSAFE_CURVE ],
    'ssh-dss-cert-v01@openssh.com':             [ SMALL_MODULUS, RANDOM_SIGNATURE ],
    'ssh-dss-cert-v00@openssh.com':             [ SMALL_MODULUS, RANDOM_SIGNATURE ],
    'ssh-dss':                                  [ SMALL_MODULUS, RANDOM_SIGNATURE ],
}

CIPHERS = {
    'chacha20-poly1305@openssh.com': None,
    'aes256-gcm@openssh.com':        None,
    'aes128-gcm@openssh.com':        None,
    'aes256-ctr':                    None,
    'aes192-ctr':                    None,
    'aes128-ctr':                    None,
    
    'aes256-cbc':                  CBC_MODE,
    'rijndael-cbc@lysator.liu.se': CBC_MODE,
    'aes192-cbc':                  CBC_MODE,
    'aes128-cbc':                  CBC_MODE,

    'blowfish-cbc':                [ SMALL_BLOCK_SIZE, CBC_MODE ],
    'cast128-cbc':                 [ SMALL_BLOCK_SIZE, CBC_MODE ],
    '3des-cbc':                    [ WEAK_CIPHER, SMALL_BLOCK_SIZE, CBC_MODE ],
    'arcfour256':                  WEAK_CIPHER,
    'arcfour128':                  WEAK_CIPHER,
    'arcfour':                     [ WEAK_CIPHER, SMALL_KEY_SIZE ],
    'none':                        PLAINTEXT,
}

MACS = {
    'hmac-sha2-512-etm@openssh.com':  None,
    'hmac-sha2-256-etm@openssh.com':  None,
    'umac-128-etm@openssh.com':       None,
    'hmac-ripemd160-etm@openssh.com': None,

    'hmac-sha2-512':                  ENCRYPT_AND_MAC,
    'hmac-sha2-256':                  ENCRYPT_AND_MAC,
    'hmac-ripemd160':                 ENCRYPT_AND_MAC,
    'umac-128@openssh.com':           ENCRYPT_AND_MAC,

    'umac-64-etm@openssh.com':      SMALL_TAG_SIZE,
    'umac-64@openssh.com':          [ ENCRYPT_AND_MAC, SMALL_TAG_SIZE ],
    'hmac-sha1-etm@openssh.com':    WEAK_HASH,
    'hmac-sha1':                    [ WEAK_HASH, ENCRYPT_AND_MAC ],
    'hmac-sha1-96-etm@openssh.com': WEAK_HASH,
    'hmac-sha1-96':                 [ WEAK_HASH, ENCRYPT_AND_MAC ],
    'hmac-md5-etm@openssh.com':     WEAK_HASH,
    'hmac-md5-96-etm@openssh.com':  WEAK_HASH,
    'hmac-md5':                     [ WEAK_HASH, ENCRYPT_AND_MAC ],
    'hmac-md5-96':                  [ WEAK_HASH, ENCRYPT_AND_MAC ],
}
