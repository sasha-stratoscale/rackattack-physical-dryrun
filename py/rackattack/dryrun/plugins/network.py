from strato.racktest.hostundertest import plugins
from rackattack.dryrun.seeds import network as seednetwork
import logging
import ipaddr
import time
from rackattack.dryrun.common import waitforpredicate
from strato.common.multithreading import subprocesswrappers


NETWORK_OFFSET = 10

SYSCONFIG_NETWORK_CONF = """DEVICE=%(device)s
HWADDR=%(mac)s
BOOTPROTO=static
IPADDR=%(ip)s
NETMASK=%(mask)s"""


class Network(object):

    def __init__(self, host):
        self._host = host
        self._mellanixPCIId = None
        self.networks = dict()

    def initialize(self):
        logging.info("Initializing fast network on host %(host)s", dict(host=self._host.name))
        self._initMellanoxDevice()
        self._configureFastNetwork()

    def addTaggedDevice(self, vport, inetAddr):
        untagedDeviceName = self.networks['untaged']['device']
        self._host.ssh.run.script("vconfig add %(deviceName)s %(vlanID)s" % dict(deviceName=untagedDeviceName, vlanID=vport))
        deviceName = "%(device)s.%(port)d" % dict(device=untagedDeviceName, port=vport)
        self._host.seed.runCallable(seednetwork.configureStaticIPOnDevice, inetAddr, deviceName)
        self.networks[vport] = dict(device=deviceName, ip=inetAddr.ip)

    def addTaggedDevices(self, vports):
        for i, vport in enumerate(vports):
            self.addTaggedDevice(vport, self._fastNetworkIpAddressFromMgmtIpAddress(i + 1))

    def _fastNetworkIpAddressFromMgmtIpAddress(self, offset=0):
        publicIpList = self._host.node.ipAddress().split('.')
        publicIpList[2] = str(int(publicIpList[2]) + NETWORK_OFFSET + offset)
        newIP = '.'.join(publicIpList)
        netAddress = ipaddr.IPv4Network('%s/%d' % (newIP, 24))
        return netAddress

    def _configureFastNetwork(self):
        try:
            privateInterface = waitforpredicate.WaitForPredicate(timeout=40, interval=3).waitAndReturn(self.fastInterface)
        except:
            interfaces = self._host.seed.runCallable(seednetwork.interfaces)[0]
            logging.exception("Failed to aquire fast interface on host %(host)s existing %(interfaces)s",
                              dict(host=self._host.name, interfaces=interfaces))
            raise

        inet = self._fastNetworkIpAddressFromMgmtIpAddress()
        device = privateInterface[0]
        mac = privateInterface[2]
        logging.info("Adding ip address %(ip)s in host %(host)s device %(device)s mac %(mac)s"
                     % dict(ip=inet.ip, host=self._host.name, device=device, mac=mac))
        self.networks['untaged'] = dict(device=device, ip=inet.ip)
        staticConfPath = '/etc/sysconfig/network-scripts/ifcfg-%(deviceName)s' % dict(deviceName=device)
        self._host.ssh.ftp.putContents(staticConfPath, SYSCONFIG_NETWORK_CONF %
                                       dict(device=device, ip=inet.ip, mac=mac, mask=inet.netmask))
        self._host.seed.runCallable(seednetwork.configureStaticIPOnDevice, inet, device)

    def _mellanoxPCICardID(self):
        lspciLines = self._host.ssh.run.script("lspci").split('\n')
        for line in lspciLines:
            if 'Mellanox' in line:
                if any(x in line for x in ['Network controller', 'Ethernet controller']):
                    return line.split(' ')[0]
        return None

    def _initMellanoxDevice(self):
        self._host.kernel.removeKernelModuleIfLoaded('mlx4_en')
        self._host.kernel.removeKernelModuleIfLoaded('mlx4_core')
        self._host.kernel.modprobe('mlx4_core', 'port_type_array=2,2')
        self._host.kernel.modprobe('mlx4_en')
        deviceName = waitforpredicate.WaitForPredicate(timeout=30, interval=3).waitAndReturn(self._mellanoxPCICardID)
        self._mellanixPCIId = deviceName
        self._host.kernel.modprobe('8021q')
        self._host.ssh.run.script("/bin/echo eth > /sys/bus/pci/devices/0000:%(deviceName)s/mlx4_port1"
                                  % dict(deviceName=deviceName))
        # Second port is not a must and in fact does not exists in bezeq cloud
        self._host.ssh.run.script("/bin/echo eth > /sys/bus/pci/devices/0000:%(deviceName)s/mlx4_port2 || true"
                                  % dict(deviceName=deviceName))

    def mellanoxPCIId(self):
        return self._mellanixPCIId

    def fastInterface(self):
        interfaces = self._host.seed.runCallable(seednetwork.interfaces)[0]
        if len(interfaces['fast']) > 0:
            return interfaces['fast'][0]
        return None

    def ethtool(self):
        return self._host.seed.runCallable(seednetwork.ethtool)[0]

    def ifconfig(self):
        self._host.ssh.run.script("ifconfig -a -v")

plugins.register('network', Network)
