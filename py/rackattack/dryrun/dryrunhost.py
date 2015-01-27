from rackattack.ssh import connection
from strato.racktest.hostundertest import plugins

import strato.racktest.hostundertest.builtinplugins.rpm
import strato.racktest.hostundertest.builtinplugins.seed
from rackattack import ssh
import paramiko

from rackattack.ssh import ftp
from rackattack.ssh import run
from rackattack.ssh import dirftp
from rackattack.ssh import tunnel


class DryRunHost(object):

    def __init__(self, node, credentials):
        self.name = node.name()
        self.ssh = ProxySSHConnection(node.masterHost, node.ipAddress(), credentials)
        self.__plugins = {}
        self.node = node

    def __getattr__(self, name):
        if name not in self.__plugins:
            self.__plugins[name] = plugins.plugins[name](self)
        return self.__plugins[name]


class ProxySSHConnection(object):

    def __init__(self, masterHost, destIp, credentials):
        self._masterHost = masterHost
        self._destIp = destIp
        self._credentials = credentials
        self._sshClient = None

    @property
    def run(self):
        return run.Run(self._sshClient)

    @property
    def ftp(self):
        return ftp.FTP(self._sshClient)

    @property
    def dirFTP(self):
        return dirftp.DirFTP(self._sshClient)

    def close(self):
        self._sshClient.close()
        self._sshClient = None

    def connect(self):
        transport = self._masterHost.ssh._sshClient.get_transport()
        dst = (self._destIp, 22)
        src = ('127.0.0.1', 0)
        commChannel = transport.open_channel("direct-tcpip", dst, src)
        self._sshClient = paramiko.client.SSHClient()
        self._sshClient.known_hosts = None
        self._sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._sshClient.connect(src[0], port=src[1], sock=commChannel, **self._credentials)
