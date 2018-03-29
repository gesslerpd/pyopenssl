# -*- coding: latin-1 -*-

"""
Simple DTLS client, using blocking I/O
"""

import os
import socket
import sys

from OpenSSL import SSL, crypto


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    sys.stdout.flush()
    return ok


if len(sys.argv) < 3:
    print('Usage: python client.py HOST PORT')
    sys.exit(1)


dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Initialize context
# ctx = SSL.Context(SSL.DTLSv1_METHOD)
ctx = SSL.Context(SSL.DTLS_CLIENT_METHOD)
ctx.set_options(SSL.OP_NO_DTLSv1)
# ctx.set_verify(
#     SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb
# )  # Demand a certificate
# ctx.use_privatekey_file(os.path.join(dir, 'client.pkey'))
# ctx.use_certificate_file(os.path.join(dir, 'client.cert'))
# ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

ctx.set_cipher_list(b"PSK-AES128-CCM8")

from OpenSSL._util import lib, ffi
from functools import wraps
class PSKClientHelper(SSL._CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as a
    PSK client callback.
    """

    def __init__(self, callback):
        super().__init__()

        @wraps(callback)
        def wrapper(ssl, hint, identity, max_identity_len, psk, max_psk_len):
            try:
                conn = SSL.Connection._reverse_mapping[ssl]

                if hint == ffi.NULL:
                    hint = None
                else:
                    # that's odd, i'd have expected something more than b"" here
                    hint = ffi.string(identity)

                app_identity, app_psk = callback(conn, hint)

                app_identity = bytes(app_identity)
                app_psk = bytes(app_psk)

                if len(app_identity) > max_identity_len:
                    raise ValueError("Identity exceeds maximum length")
                if len(app_psk) > max_psk_len:
                    raise ValueError("Key exceeds maximum PSK length")

                identity[0:len(app_identity)] = app_identity
                psk[0:len(app_psk)] = app_psk

                return len(app_psk)
            except Exception as e:
                import logging
                logging.exception(e)
                self._problems.append(e)
                return 0  # context not found

        self.callback = ffi.callback(
            ("unsigned int(*)(SSL *, char *, char *, unsigned int, unsigned char *, unsigned int)"),
            wrapper
        )
def cb(*args):
    print("Arguments are", args)
    print("Returning static key anyhow")
    return (b'pytradfri', b'N6XzPGY7CP9QEgP0')
wrapped = PSKClientHelper(cb).callback # reference needs to be kept around!
lib.SSL_CTX_set_psk_client_callback(ctx._context, wrapped)

# Set up client
sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
sock.connect((sys.argv[1].encode('ascii'), int(sys.argv[2])))


print(sock._socket.getsockname())
sys.stdout.flush()

# do handshake on connect
# sock.do_handshake()

while 1:
    line = sys.stdin.readline()
    if line == '' or line == '\n':
        break
    try:
        sock.send(line)
        sys.stdout.write(sock.recv(1024).decode('utf-8'))
        sys.stdout.flush()
    except SSL.Error:
        print('Connection died unexpectedly')
        break


sock.shutdown()
sock.close()
