#!/usr/bin/env python3
#
# Copyright (c) 2019 Christophe Guillon
# Copyright (c) 2018 Artem Golubin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# This work is a derivative work from the toy socks server published
# at https://github.com/rushter/socks5
# which is itself under the MIT license and copyright reproduced above.
#

#
# socks-relay implements a SOCK5 server which can optionally relay to
# a further SOCKS5 server.
# A typical use case is to expose a no-auth server in front of an authenticating
# server.
#
# For instance install a socks server bound to localhost:1080
# with auth user1/password1 which relays to another socks server
# socks.example.org:1080 with auth user2/password2:
#
#     SERVER_USER=user1 SERVER_PASSWORD=password1 SOCKS5_SERVER=socks.example.org:1080 \
#       SOCKS5_USER=user2 SOCKS5_PASSWORD=password2 ./socks-relay.py localhost:1080'
#
# Or the same with no password for the local server:
#
#     SOCKS5_SERVER=socks.example.org:1080 SOCKS5_USER=user2 SOCKS5_PASSWORD=password2 \
#       ./socks-relay.py localhost:1080
#


import sys, os
import logging
import select
import socket
import selectors
import struct
import socks
import time
from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler

logger = logging.getLogger("socks-relay")
logger_hdl = logging.StreamHandler()
logger_hdl.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s'))
logger.addHandler(logger_hdl)
logger.setLevel(logging.INFO)

SOCKS_VERSION = 5

SOCKS5_METHOD_NOAUTH = 0x00
SOCKS5_METHOD_GSSAPI = 0x01
SOCKS5_METHOD_USERPASS = 0x02
SOCKS5_METHOD_NONE_ACCEPTABLE = 0xFF
SOCKS5_METHODS = {
    SOCKS5_METHOD_NOAUTH: 'NO AUTHENTICATION REQUIRED',
    SOCKS5_METHOD_GSSAPI: 'GSSAPI',
    SOCKS5_METHOD_USERPASS: 'USERNAME/PASSWORD',
    SOCKS5_METHOD_NONE_ACCEPTABLE: 'NO ACCEPTABLE METHODS'
}

SOCKS5_ATYPE_IPV4 = 0x01
SOCKS5_ATYPE_DOMAIN = 0x03
SOCKS5_ATYPE_IPV6 = 0x04
SOCKS5_ATYPES = {
    SOCKS5_ATYPE_IPV4: 'IPV4',
    SOCKS5_ATYPE_DOMAIN: 'DOMAINNAME',
    SOCKS5_ATYPE_IPV6: 'IPV6',
}

SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_BIND = 0x02
SOCKS5_CMD_UDP_ASSOCIATE = 0x03
SOCKS5_CMDS = {
    SOCKS5_CMD_CONNECT: 'CONNECT',
    SOCKS5_CMD_BIND: 'BIND',
    SOCKS5_CMD_UDP_ASSOCIATE: 'UDP ASSOCIATE',
}


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class ConnectionInterrupted(Exception):
    pass

class SocksProxy(BaseRequestHandler):

    def setup(self):
        super(SocksProxy, self).setup()
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.username = os.environ.get('SERVER_USER', None)
        self.password = os.environ.get('SERVER_PASSWORD', None)
        proxy_server = os.environ.get('SOCKS5_SERVER', None)
        if proxy_server != None:
            self.proxy_host, self.proxy_port = proxy_server.split(":")
            self.proxy_port = int(self.proxy_port)
        else:
            self.proxy_host, self.proxy_port = (None, None)
        self.proxy_username = os.environ.get('SOCKS5_USER', None)
        self.proxy_password = os.environ.get('SOCKS5_PASSWORD', None)

    def finish(self):
        super(SocksProxy, self).finish()

    def recv(self, sock, n):
        try:
            return sock.recv(n)
        except Exception as e:
            raise ConnectionInterrupted('in recv() %s: %s' % (sock, e))

    def recvall(self, sock, n):
        parts = []
        total = 0
        while total < n:
            try:
                part = sock.recv(n - total)
            except Exception as e:
                raise ConnectionInterrupted('in recvall() %s: %s' % (sock, e))
            if len(part) == 0: break
            total += len(part)
            parts.append(part)
        if total < n:
            raise ConnectionInterrupted('in recvall() %s: unexpected end of stream' % sock)
        return b''.join(parts)

    def sendall(self, sock, msg):
        try:
            return sock.sendall(msg)
        except Exception as e:
            raise ConnectionInterrupted('sock.sendall %s: %s' % (sock, e))

    def handle(self):
        logger.info('client %s: Accepting connection: %s' % (self.client_address, self.request))
        try:
            # greeting header
            header = self.recvall(self.request, 2)
            version, nmethods = struct.unpack("!BB", header)

            # asserts socks 5
            assert version == SOCKS_VERSION
            assert nmethods > 0

            # get available methods
            methods = set(self.recvall(self.request, nmethods))

            # accept only NOAUTH or USERPASS auth
            if ((self.username and self.password and not SOCKS5_METHOD_USERPASS in methods) or
                (not SOCKS5_METHOD_NOAUTH in methods)):
                self.sendall(self.request, struct.pack("!BB", SOCKS_VERSION, SOCKS5_METHOD_NONE_ACCEPTABLE))
                return

            # send welcome message
            if self.username and self.password:
                self.sendall(self.request, struct.pack("!BB", SOCKS_VERSION, SOCKS5_METHOD_USERPASS))
                if not self.verify_credentials():
                    return
            else:
                self.sendall(self.request, struct.pack("!BB", SOCKS_VERSION, SOCKS5_METHOD_NOAUTH))

            # request
            version, cmd, _, address_type = struct.unpack("!BBBB", self.recvall(self.request, 4))
            assert version == SOCKS_VERSION

            if address_type not in [SOCKS5_ATYPE_IPV4, SOCKS5_ATYPE_DOMAIN]:
                logger.error("client %s: Address Type not supported: %d (%s)" % (self.client_address, address_type, SOCKS5_ATYPES.get(address_type, "unknown")))
                reply = self.generate_failed_reply(0x08) # Address type not supported
                self.sendall(self.request, reply)
                return

            if address_type == SOCKS5_ATYPE_IPV4:
                address = socket.inet_ntoa(self.recvall(self.request, 4))
            elif address_type == SOCKS5_ATYPE_DOMAIN:
                domain_length = self.recvall(self.request, 1)[0]
                address = self.recvall(self.request, domain_length).decode('ascii')
            port = struct.unpack('!H', self.recvall(self.request, 2))[0]

            logger.info("client %s: Received command %d for %s:%s" % (self.client_address, cmd, address, port))

            if cmd not in [SOCKS5_CMD_CONNECT]:
                logger.error("client %s: Command not supported: %d (%s)" % (self.client_address, cmd, SOCKS5_CMDS.get(cmd, "unknown")))
                reply = self.generate_failed_reply(0x07) # Command not supported
                self.sendall(self.request, reply)
                return

            if self.proxy_host and self.proxy_port:
                socket_class = socks.socksocket
            else:
                socket_class = socket.socket

            with socket_class() as remote:
                try:
                    if self.proxy_host and self.proxy_port:
                        remote.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port, username=self.proxy_username, password=self.proxy_password)
                    remote.connect((address, port))
                except Exception as err:
                    logger.error("client %s: could not connect to remote: %s" % (self.client_address, err))
                    reply = self.generate_failed_reply(0x05) # Connection refused
                    self.sendall(self.request, reply)
                    return

                logger.info('client %s: Connected to %s:%s: %s' % (self.client_address, address, port, remote))

                bind_address = remote.getsockname()
                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, SOCKS5_ATYPE_IPV4, addr, port)
                self.sendall(self.request, reply)

                self.exchange_loop(self.request, remote)
        except ConnectionInterrupted as e:
            logger.info("client %s: Connection interrupted: %s" % (self.client_address, e))
        finally:
            self.server.close_request(self.request)
            logger.info('client %s: Closed connection' % (self.client_address,))

    def verify_credentials(self):
        version = self.recvall(self.request, 1)[0]
        assert version == 1

        username_len = self.recvall(self.request, 1)[0]
        username = self.recvall(self.request, username_len).decode('utf-8')

        password_len = self.recvall(self.request, 1)[0]
        password = self.recvall(self.request, password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.sendall(self.request, response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.sendall(self.request, response)
        return False

    def generate_failed_reply(self, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, SOCKS5_ATYPE_IPV4, 0, 0)

    def exchange_loop(self, client, remote):
        sel = selectors.DefaultSelector()
        client.setblocking(False)
        sel.register(client, selectors.EVENT_READ, remote)
        remote.setblocking(False)
        sel.register(remote, selectors.EVENT_READ, client)
        while len(sel.get_map().keys()) == 2:
            events = sel.select()
            for key, mask in events:
                data = self.recv(key.fileobj, 4096)
                if len(data) > 0:
                    self.sendall(key.data, data)
                else:
                    sel.unregister(key.fileobj)
        sel.close()


if __name__ == '__main__':
    host, port = sys.argv[1].split(":")
    if host == "": host = 'localhost'
    elif host == "*": host = '0.0.0.0'
    port = int(port)
    logger.info("Socks relay listening for %s:%d" % (host, port))
    try:
        server = ThreadingTCPServer((host, port), SocksProxy)
    except OSError as e:
        if e.errno == 98:
            logger.error("cannot bind %s:%d: %s" % (host, port, e))
            sys.exit(1)
        raise
    try:
        server.serve_forever()
    finally:
        server.server_close()

