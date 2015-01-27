import logging
import socket
import functools
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
import argparse
import threading
from rackattack.common import tftpboot
from rackattack.common import dnsmasq
from rackattack.common import inaugurate
from rackattack.physical import ipmi
from rackattack.physical import serialoverlan
from rackattack.common import globallock
import time
import network


class Waiter:

    def __init__(self, nodes):
        self.nodes = nodes
        self.condition = threading.Condition()

    def notifyOne(self, checkedInNode):
        self.condition.acquire()
        self.nodes = [node for node in self.nodes if node is not checkedInNode]
        if len(self.nodes) == 0:
            self.condition.notifyAll()
        self.condition.release()

    def waitAll(self, timeout=None):
        self.condition.acquire()
        self.condition.wait(timeout=timeout)
        self.condition.release()
        return self.nodes


def waitForTCPServer(hostname, port, timeout=60, interval=0.1):
    before = time.time()
    while time.time() - before < timeout:
        if _rawTCPConnect((hostname, port)):
            return
        time.sleep(interval)
    raise Exception("SSH TCP Server '%(hostname)s:%(port)s' did not respond within timeout" % dict(hostname=hostname, port=port))


def _rawTCPConnect(tcpEndpoint):
    s = socket.socket()
    try:
        s.connect(tcpEndpoint)
        return True
    except:
        return False
    finally:
        s.close()


def inaugurateCheckIn(inaugurateInstance, innaguratedNode, rootfsLabel, notifier):
    logging.info("Inaugurator checked in")
    inaugurateInstance.provideLabel(ipAddress=innaguratedNode['ipAddress'], label=rootfsLabel)
    notifier.notifyOne(innaguratedNode)


def inaugurateDone(innaguratedNode, notifier):
    logging.info("Inaugurator checked in")
    notifier.notifyOne(innaguratedNode)


def _prepareForInnauguration(dnsmasqInstance, inaugurateInstance, tftpbootInstance,
                             nodesToInnagurate, rootfsLabel, checkinWaiter, doneWaiter):
    with globallock.lock():
        for nodeToInnaugurate in nodesToInnagurate:
            dnsmasqInstance.add(nodeToInnaugurate['macAddress'], nodeToInnaugurate['ipAddress'])
            checkInCallback = functools.partial(inaugurateCheckIn,
                                                inaugurateInstance,
                                                nodeToInnaugurate,
                                                rootfsLabel,
                                                checkinWaiter)
            doneCallback = functools.partial(inaugurateDone,
                                             innaguratedNode=nodeToInnaugurate,
                                             notifier=doneWaiter)
            inaugurateInstance.register(ipAddress=nodeToInnaugurate['ipAddress'],
                                        checkInCallback=checkInCallback,
                                        doneCallback=doneCallback)
            tftpbootInstance.configureForInaugurator(nodeToInnaugurate['macAddress'],
                                                     nodeToInnaugurate['ipAddress'],
                                                     clearDisk=True)


def innaugurate(osmosisServerIP, rootfsLabel, nodesToInnagurate):
    network.dropFirewall()
    logging.info("MyIP: %(ip)s", dict(ip=network.myIP()))

    tftpbootInstance = tftpboot.TFTPBoot(
        netmask=network.netmask(),
        inauguratorServerIP=network.myIP(),
        osmosisServerIP=osmosisServerIP,
        inauguratorGatewayIP=network.myIP(),
        rootPassword="dryrun",
        withLocalObjectStore=True)
    dnsmasq.DNSMasq.eraseLeasesFile()
    dnsmasq.DNSMasq.killAllPrevious()
    dnsmasqInstance = dnsmasq.DNSMasq(
        tftpboot=tftpbootInstance,
        serverIP=network.myIP(),
        netmask=network.netmask(),
        firstIP=nodesToInnagurate[0]['ipAddress'],
        lastIP=nodesToInnagurate[0]['ipAddress'],
        gateway=network.gateway(),
        nameserver=network.myIP())

    logging.info("Sleeping 1 second to let dnsmasq go up, so it can receive SIGHUP")
    time.sleep(1)
    logging.info("Done Sleeping 1 second to let dnsmasq go up, so it can receive SIGHUP")
    inaugurateInstance = inaugurate.Inaugurate(bindHostname=network.myIP())

    checkinWaiters = Waiter(nodesToInnagurate)
    doneWaiters = Waiter(nodesToInnagurate)
    _prepareForInnauguration(dnsmasqInstance, inaugurateInstance,
                             tftpbootInstance, nodesToInnagurate, rootfsLabel,
                             checkinWaiters, doneWaiters)
    solReaders = dict()
    for nodeToInnaugurate in nodesToInnagurate:
        sol = serialoverlan.SerialOverLan(nodeToInnaugurate['ipmiHost'],
                                          nodeToInnaugurate['ipmiUsername'],
                                          nodeToInnaugurate['ipmiPassword'],
                                          nodeToInnaugurate['hostID'])
        solReaders[nodeToInnaugurate['macAddress']] = sol

    for nodeToInnaugurate in nodesToInnagurate:
        ipmiInstance = ipmi.IPMI(nodeToInnaugurate['ipmiHost'],
                                 nodeToInnaugurate['ipmiUsername'],
                                 nodeToInnaugurate['ipmiPassword'])
        ipmiInstance.forceBootFrom('pxe')
        ipmiInstance.powerCycle()

    logging.info("Waiting for inaugurator to check in")
    failedNodesList = []
    failedToCheckinNodes = checkinWaiters.waitAll(timeout=10 * 60)
    logging.error("Failed to checkin nodes %(nodes)s", dict(nodes=failedToCheckinNodes))
    for nodeNotToWaitDone in failedToCheckinNodes:
        doneWaiters.notifyOne(nodeNotToWaitDone)
    notDoneNodes = doneWaiters.waitAll(timeout=10 * 60)
    failedNodesList.extend(failedToCheckinNodes)
    failedNodesList.extend(notDoneNodes)
    logging.error("Failed to finish nodes %(nodes)s", dict(nodes=notDoneNodes))

    nodesToWaitForIp = [node for node in nodesToInnagurate if node not in notDoneNodes]
    # Now wait for all servers to obtain an IP
    for nodeToInnaugurate in nodesToWaitForIp:
        try:
            waitForTCPServer(nodeToInnaugurate['ipAddress'], 22)
        except:
            logging.exception("Failed to wait for active ssh connection on %(node)s",
                              dict(node=nodesToInnagurate['hostID']))
            failedNodesList.append(nodeToInnaugurate)

    failedNodes = {node['hostID']: open(solReaders[node['macAddress']].serialLogFilename()).read()
                   for node in failedNodesList}
    return failedNodes
