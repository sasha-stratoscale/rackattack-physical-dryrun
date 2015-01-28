from strato.racktest.hostundertest import plugins
from strato.common import log
import logging
import time
import os


TAR_COMMAND = """tar -c --warning=no-file-changed --use-compress-program=pigz -f %(targetpath)s %(srcPath)s
exitcode=$?
if [ "$exitcode" != "1" ] && [ "$exitcode" != "0" ]; then
    exit $exitcode
fi
exit 0
"""


class LogPlugin:

    def __init__(self, host):
        self._host = host

    def prepareForDownload(self, path):
        tarFileName = LogPlugin._remoteTarFileName()
        tarFilePath = os.path.join("/tmp", tarFileName)
        self._host.ssh.run.script(TAR_COMMAND % dict(targetpath=tarFilePath, srcPath=path))
        return tarFilePath

    def download(self, tarFilePath):
        localTarPath = self._localTarFilePath(log.config.LOGS_DIRECTORY)
        localTarDir = os.path.dirname(localTarPath)
        if not os.path.exists(localTarDir):
            os.makedirs(localTarDir)
        self._host.ssh.ftp.getFile(tarFilePath, localTarPath)

    def prepareAndDownload(self, path):
        zipedFilePath = self.prepareForDownload(path)
        self.download(zipedFilePath)

    def _localTarFilePath(self, localDir):
        return os.path.join(localDir, "logs.%(hostName)s" % dict(hostName=self._host.name), "logs.tar.gz")

    @staticmethod
    def _remoteTarFileName():
        return "racktest.logplugin.%s.tar.gz" % time.strftime("%Y%m%d%H%M%S")

plugins.register("log", LogPlugin)
