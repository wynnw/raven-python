"""
raven.contrib.transports.unixdomainsocket
~~~~~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2010-2012 by the Sentry Team, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
from socket import socket, AF_UNIX, SOCK_STREAM, error as socket_error
from raven.transport import Transport


class UnixDomainSocketTransport(Transport):
    """transport for writing over a local unix domain socket
      url scheme is: unix://<pubkey>:<privkey>@<projkey>/<domain socket path>
      it uses SOCK_STREAM to avoid dropping udp datagrams, as most unix systems
      have their max datagram size for domain sockets pretty low - around 2k
      see net.local.dgram.maxdgram for example on darwin/bsd
    """
    scheme = ['unix']

    def __init__(self, parsed_url):
        if not has_socket:
            raise ImportError('UnixDomainSocketTransport requires the socket module')
        self.check_scheme(parsed_url)
        self.sockpath = parsed_url.path
        self.sock = None

    def _sock(self):
        if self.sock is None:
            try:
                self.sock = socket(AF_UNIX, SOCK_STREAM)
                self.sock.setblocking(False)
                self.sock.connect(self.sockpath)
            except socket_error:
                if self.sock:
                    self.sock.close()
                    self.sock = None

        return self.sock

    def send(self, data, headers):
        """send data to the local sentry proxy. ignore the headers - the proxy will take care of that"""
        sock = self._sock()
        if sock is None:
            return  # no socket - have to fail
        for chunk in [struct.pack('I', len(data)), data]:
            sock.send(chunk)

    def compute_scope(self, url, scope):
        project = url.hostname

        if not all([project, url.username, url.password]):
            raise ValueError('Invalid Sentry DSN: %r' % url.geturl())

        server = urlunparse(url)
        scope.update({
            'SENTRY_SERVERS': [server],
            'SENTRY_PROJECT': project,
            'SENTRY_PUBLIC_KEY': url.username,
            'SENTRY_SECRET_KEY': url.password,
        })
        return scope


from raven import Client
Client.register_scheme('unix', UnixDomainSocketTransport)

