# socks-relay

Simple socks5 server with either no-auth or user-pass authentication.

The server can itself realy to another socks5 server using or not authentication.

As a simple test, run a local socks server and connect to a ssh server:

    SERVER_USER=user1 SERVER_PASSWORD=password1 ./socks-relay.py localhost:1080
	... socks-relay INFO Socks relay listening for localhost:1080
	...
	# in another terminal connect to github.com through the socks proxy
	connect-proxy -S user1@localhost:1081 github.com 22
	Enter SOCKS5 password for user1@localhost: password1
	SSH-2.0-babeld-f3847d63
	...


A typical use case is to expose a no-auth server in front of an authenticating
server.

For instance install a socks server bound to localhost:1080
with auth user1/password1 which relays to another socks server
socks.example.org:1080 with auth user2/password2:

     SERVER_USER=user1 SERVER_PASSWORD=password1 SOCKS5_SERVER=socks.example.org:1080 \
       SOCKS5_USER=user2 SOCKS5_PASSWORD=password2 ./socks-relay.py localhost:1080'

Or the same with no password for the local server:

    SOCKS5_SERVER=socks.example.org:1080 SOCKS5_USER=user2 SOCKS5_PASSWORD=password2 \
      ./socks-relay.py localhost:1080


More access control can be given through the following variables:

- `SERVER_CLIENTS_ALLOWED`: comma-separated list of regexp allowed for connection, defaults to `.*`.
  For instance `SERVER_CLIENTS_ALLOWED='127\..*\..*\..*` will allow only connetion from client addresses starting with `127.`.
- `SERVER_CLIENTS_REFUSED`: comma-separated list of regexp refused for connection, processed after allowed list.
  For instance `SERVER_CLIENTS_REFUSED='10\..*\..*\..*` will refuse any connection from client address starting with `10.`.
- `SERVER_REMOTES_ALLOWED`: comma-separated list of regexp for hostname allowed to connect to, defaults to `.*`. Note that
  for remotes, both numeric IP addresses or hostnames can be given by the client.
  For instance `SERVER_REMOTES_ALLOWED=github.com` will allow only connections to `github.com`.
- `SERVER_REMOTES_REFUSED`: comma-separated list of regexp for hostname not allowed to connect to, processed after allowed list.
  For instance `SERVER_REMOTES_REFUSED=github.com` will refuse connections to `github.com`.


Also static remote hosts resolution can be given with a map encoded in the
`SERVER_RESOLVE_MAP` variable. For instance: `SERVER_RESOLVE_MAP='loopback=>127.0.0.1,::1=>loopback'` will
resolve `::1` to `127.0.0.1` before connecting to `127.0.0.1`. Resolution happens after remotes host filtering.

This scripts requires `python3` and the `pysocks` module, install it for instance with:

    pip3 install --user pysocks


This script is a derivative work from the toy socks server published
at https://github.com/rushter/socks5
which is itself under the MIT license and copyright reproduced in the script
comments and in the `LICENSE` file.
