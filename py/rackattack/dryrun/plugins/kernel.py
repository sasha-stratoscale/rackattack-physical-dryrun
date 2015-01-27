from strato.racktest.hostundertest import plugins
from rackattack.dryrun.seeds import cpuinfo
from rackattack.dryrun.lib import cpuinfo as libcpuinfo
from strato.common.multithreading import waittonotthrow
import logging


class Kernel:

    def __init__(self, host):
        self._host = host

    def version(self):
        return self._host.ssh.run.script("uname -r")

    def is_debug(self):
        return "debug" in self.version()

    def cpuinfo(self):
        return libcpuinfo.CpuInfo(self._host.seed.runCallable(cpuinfo.cpuInfo)[0])

    def rdmsr(self, register):
        return self._host.ssh.run.script("rdmsr %(regnum)s" % dict(regnum=register)).strip()

    def modprobe(self, module, parameters=""):
        try:
            self._host.ssh.run.script("modprobe %(module)s %(parameters)s" % dict(module=module, parameters=parameters))
        except:
            self._logDmesgOnModuleLoadFailure(module)
            raise

    def removeKernelModuleIfLoaded(self, module):
        if self.isModuleLoaded(module):
            self.removeKernelModule(module)

    def removeKernelModule(self, module):
        TIME_WAIT_FOR_RMMOD_TO_SUCCEEDD = 10
        waittonotthrow.WaitToNotThrow(timeout=TIME_WAIT_FOR_RMMOD_TO_SUCCEEDD).wait(lambda: self._host.ssh.run.script("rmmod %s" % module))

    def isModuleLoaded(self, module):
        output = self._host.ssh.run.script("lsmod")
        return module in output.split()

    def _logDmesgOnModuleLoadFailure(self, moduleName):
        # We assume that if we fail here it is because of some module dependencies, lets log last lines from dmesg
        try:
            logging.error('Failed to modprobe module %(module)s dmesg: %(dmesg)s', dict(module=moduleName, dmesg=self.dmesg(30)))
        except:
            pass  # If fail on dmesg, ignore nothing we can do about it


plugins.register('kernel', Kernel)
