from strato.racktest.hostundertest import plugins
from rackattack.dryrun.seeds import cpuinfo
from rackattack.dryrun.lib import cpuinfo as libcpuinfo
import logging


class Disk:

    def __init__(self, host):
        self._host = host

    def smartctlStatus(self, deviceToCheck):
        output = self._host.ssh.run.script("smartctl -H %(device)s" % dict(device=deviceToCheck)).strip()
        return ('PASSED' in output, output)

    def rotational(self, deviceName):
        return 1 == int(self._host.ssh.run.script('cat /sys/block/%(device)s/queue/rotational' % dict(device=deviceName)).strip())

plugins.register('disk', Disk)
