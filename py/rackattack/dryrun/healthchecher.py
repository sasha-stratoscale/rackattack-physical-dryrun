import logging
from rackattack.dryrun.common import waitforpredicate
from strato.common.multithreading import concurrently
import pprint
import servertestresult
import threading
import sys


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
    return "ping -c 2 %(ip)s -I %(device)s" % dict(ip=ip, device=deviceName)


def _runPing(srcHost, dstHost, netName, testResult, lock):
    ipDst = dstHost.network.networks[netName]['ip']
    srcDevice = srcHost.network.networks[netName]['device']
    log = ''
    pingScript = _pingScript(ipDst, srcDevice)
    try:
        srcHost.ssh.run.script(pingScript)
        lock.acquire()
        testResult.addCheck('net', 'ping on %(netName)s from %(src)s to %(dest)s "%(script)s"' %
                            dict(netName=netName, src=srcHost.name, dest=dstHost.name, script=pingScript),
                            True, '', (netName, srcHost.name, dstHost.name))
        lock.release()
    except:
        log = "Failed pinging from host %(srchost)s to %(dstHost)s to ip %(ip)s" % dict(
            srchost=srcHost.name, dstHost=dstHost.name, ip=ipDst)
        lock.acquire()
        testResult.addCheck('net', 'ping on %(netName)s from %(src)s to %(dest)s "%(script)s" exception %(exception)s' %
                            dict(netName=netName, src=srcHost.name, dest=dstHost.name, script=pingScript, exception=sys.exc_info()[1].message),
                            False, log, (netName, srcHost.name, dstHost.name))
        lock.release()


def _checkNetwork(node1, node2, vlanTags, testResult, lock):
    for netName in ['untaged'] + vlanTags:
        _runPing(node1, node2, netName, testResult, lock)
        _runPing(node2, node1, netName, testResult, lock)


def checkServer(serverToCheck, serversToCheckNetwork, testResult, vlanTags):
    logging.info("Going to check %(server)s", dict(server=serverToCheck.name))
    _verifyVirtualizationEnabled(serverToCheck, testResult)
    _checkDisk(serverToCheck, testResult)
    lock = threading.Lock()
    jobs = {server.name: (_checkNetwork, server, serverToCheck, vlanTags, testResult, lock)
            for server in serversToCheckNetwork}
    concurrently.run(jobs, numberOfThreads=30)
    return testResult


def _partnerServer(masterHost, serversToCheck, serverToCheck):
    return [masterHost] + [server for server in serversToCheck if server is not serverToCheck]


def checkServers(masterHost, hostsToProced, vlanTags):
    allHosts = [host['host'] for host in hostsToProced]
    jobs = {host['name']: (checkServer, host['host'], _partnerServer(masterHost, allHosts, host['host']), host['result'], vlanTags)
            for host in hostsToProced}
    concurrently.run(jobs, numberOfThreads=10)
