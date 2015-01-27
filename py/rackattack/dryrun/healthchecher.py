import logging
from rackattack.dryrun.common import waitforpredicate
from strato.common.multithreading import concurrently
import pprint
import servertestresult
import threading


def _verifyVmxEnabledByBios(host, resultObject):
    IA32_FEATURE_CONTROL = '0x3a'
    VMXON_BIT = 2
    LOCK_BIT = 0
    VMX_ENABLED = ((1 << VMXON_BIT) | (1 << LOCK_BIT))
    regvalue = int(host.kernel.rdmsr(IA32_FEATURE_CONTROL))
    result = True
    log = ''
    if(regvalue & VMX_ENABLED) != VMX_ENABLED:
        log = "VMX is not enabled in bios register val %(regvalue)" % dict(regvalue=hex(regvalue))
        result = False
    resultObject.addCheck('virt', 'virtualization bios', result, log)


def _verifyVirtualizationEnabled(host, resultObject):
    info = host.kernel.cpuinfo()
    output = ''
    result = True
    if not info.hasVt():
        result = False
        output = "Virtualization is not supported on %(hostname)s cpuninfo %(cpuinfo)s" % dict(
            hostname=host.name, cpuinfo=pprint.pprint(info))
    resultObject.addCheck('virt', 'virtualization cpu support', result, output)
    if info.hasFlag(0, 'vmx'):
        _verifyVmxEnabledByBios(host, resultObject)


def _checkDisk(hostToCheck, resultObject):
    result, output = hostToCheck.disk.smartctlStatus('/dev/sda')
    resultObject.addCheck('disk', 'smartctl /dev/sda', result, output)
    resultObject.addCheck('disk', 'SSD /dev/sda', not hostToCheck.disk.rotational('sda'))


def _pingScript(ip, deviceName):
    return "ping -c 5 %(ip)s -I %(device)s" % dict(ip=ip, device=deviceName)


def _runPing(srcHost, dstHost, netName, testResult, lock):
    ipDst = dstHost.network.networks[netName]['ip']
    srcDevice = srcHost.network.networks[netName]['device']
    logging.info("Pinging from host %(srchost)s to %(dstHost)s to ip %(ip)s from device %(srcDevice)s", dict(
        srchost=srcHost.name, dstHost=dstHost.name, ip=ipDst, srcDevice=srcDevice))
    log = ''
    result = True
    pingScript = _pingScript(ipDst, srcDevice)
    try:
        srcHost.ssh.run.script(pingScript)
    except:
        result = False
        log = "Failed pinging from host %(srchost)s to %(dstHost)s to ip %(ip)s" % dict(
            srchost=srcHost.name, dstHost=dstHost.name, ip=ipDst)
        logging.exception(log)
        lock.acquire()
        testResult.addCheck('net', 'ping on %(netName)s from %(src)s to %(dest)s "%(script)s"' %
                            dict(netName=netName, src=srcHost.name, dest=dstHost.name, script=pingScript),
                            result, log)
        lock.release()


def _checkNetwork(node1, node2, vlanTags, testResult, lock):
    for netName in ['untaged'] + vlanTags:
        logging.info("Checking '%(network)s' network between %(node1)s and %(node2)s",
                     dict(network=str(netName), node1=node1.name, node2=node2.name))
        _runPing(node1, node2, netName, testResult, lock)
        _runPing(node2, node1, netName, testResult, lock)


def checkServer(serverToCheck, serversToCheckNetwork, testResult, vlanTags):
    _verifyVirtualizationEnabled(serverToCheck, testResult)
    _checkDisk(serverToCheck, testResult)
    lock = threading.Lock()
    jobs = {server.name: (_checkNetwork, server, serverToCheck, vlanTags, testResult, lock)
            for server in serversToCheckNetwork}
    concurrently.run(jobs, numberOfThreads=10)
    logging.info('Checking server %(server)s done result %(summary)s',
                 dict(server=serverToCheck.name, summary=testResult.summary()))
    return testResult


def _partnerServer(masterHost, serversToCheck, serverToCheck):
    return [masterHost] + [server for server in serversToCheck if server is not serverToCheck]


def checkServers(masterHost, hostsResultsMap, vlanTags):
    serversToCheck = hostsResultsMap.keys()
    jobs = {server.name: (checkServer, server, _partnerServer(masterHost, serversToCheck, server), testResult, vlanTags)
            for server, testResult in hostsResultsMap.items()}
    concurrently.run(jobs, numberOfThreads=10)
