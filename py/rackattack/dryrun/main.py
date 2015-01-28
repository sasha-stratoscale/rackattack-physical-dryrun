import logging
import paramiko
from strato.common.log import configurelogging
import pprint
import sys
from rackattack.dryrun import servertestresult
import traceback
import copy
configurelogging.configureLogging('dryrun', forceDirectory='logs')
import yaml
import argparse
from rackattack import api
from rackattack.ssh import connection
import subprocess
import socket
import time
import healthchecher
from rackattack import clientfactory
from rackattack.physical import ipmi
from plugins import kernel
from plugins import disk
from plugins import network
from plugins import logplugin
from strato.racktest.hostundertest import host
from rackattack.dryrun import dryrunhost
from rackattack.dryrun import node
from rackattack.dryrun.seeds import innaugurator
from strato.common.multithreading import concurrently


parser = argparse.ArgumentParser()
parser.add_argument("--rackYaml", required=True)
parser.add_argument("--rackattackUser", required=True)
parser.add_argument("--osmosisServerIP", required=True)
parser.add_argument("--ipAddress", required=True, action='append')
parser.add_argument("--targetNode", required=True, action='append')
parser.add_argument("--vlan", action='append', default=[], type=int)
parser.add_argument("--debug", action='store_true')
parser.add_argument("--noClearDisk", action='store_true')


args = parser.parse_args()


def allocateMasterHost(rackuser, label):
    client = clientfactory.factory()
    logging.info("Allocating master node")
    allocationInfo = api.AllocationInfo(user=rackuser, purpose="dryrun")
    requirements = dict(master=api.Requirement(imageLabel=label, imageHint="rootfs-basic"))
    allocation = client.allocate(requirements, allocationInfo)
    allocation.wait(timeout=5 * 60)
    logging.info("Allocation successful, waiting for ssh")
    masterHost = host.Host(allocation.nodes()['master'], 'master')
    masterHost.ssh.waitForTCPServer()
    masterHost.ssh.connect()
    return masterHost


def _allocateTestNodes(masterHost, hostsToInnagurate):
    innaguratedHosts = []
    logging.info("Going to innagurate %(servers)d servers...be patient", dict(servers=len(hostsToInnagurate)))

    hostDescriptors = [host['props'] for host in hostsToInnagurate]
    failedNodes, log = masterHost.seed.runCallable(innaugurator.innaugurate,
                                                   osmosisServerIP=args.osmosisServerIP,
                                                   rootfsLabel=label,
                                                   nodesToInnagurate=hostDescriptors,
                                                   noClearDisk=args.noClearDisk,
                                                   outputTimeout=30 * 60)
    if len(failedNodes) > 0:
        logging.error("Failed to innagurate %(nodes)d nodes log %(log)s", dict(nodes=len(failedNodes), log=log))

    for host in hostsToInnagurate:
        if host['name'] in failedNodes:
            host['result'].addCheck('init', 'innaugurate', False, failedNodes[host['name']])
        else:
            host['result'].addCheck('init', 'innaugurate', True)
            host['host'] = dryrunhost.DryRunHost(host['node'], dict(username='root', password='dryrun'))
            host['host'].ssh.connect()
            innaguratedHosts.append(host)

    return innaguratedHosts


def _allocateTestNodesInChunks(masterHost, hostsToInnagurate):
    chunks = lambda l, n: [l[x: x + n] for x in xrange(0, len(l), n)]
    hostsToInnagurateInChunks = chunks(hostsToInnagurate, 50)
    totalInnauguratedHosts = []
    for hostsChunk in hostsToInnagurateInChunks:
        totalInnauguratedHosts.extend(_allocateTestNodes(masterHost, hostsChunk))
    return totalInnauguratedHosts


def findNetworkCliques(hosts, networksToCheck):
    import networkx
    netGraph = networkx.Graph()
    netGraph.add_nodes_from([host['host'].name for host in hosts])
    networkGraphs = {networkname: netGraph.copy() for networkname in networksToCheck}

    for host in hosts:
        netChecks = host['result']['net']
        if netChecks is not None:
            for netCheck in netChecks:
                checkName = netCheck[0]
                extra = netCheck[3]
                if netCheck[1]:
                    if 'ping on' in checkName and extra is not None:
                        (netName, srcHost, dstHost) = extra
                        networkGraphs[netName].add_edge(srcHost, dstHost)

    networkCliques = {networkName: list(networkx.find_cliques(networkGraph)) for networkName, networkGraph in networkGraphs.items()}
    return networkCliques


def printServerResults(hosts):
    passedServers = []
    failedServers = []
    for host in hosts.values():
        (passedServers, failedServers)[0 if host['result'].passed() else 1].append(host['result'])

    print "TOTALLY %d PASSED %d FAILED" % (len(passedServers), len(failedServers))

    print "*********************FAILED SERVERS*******************************"
    pp = pprint.PrettyPrinter(indent=4)
    for server in failedServers:
        print("%(name)s - %(summary)s" % dict(name=server['name'], summary=str(server.summary())))
    print "*********************FAILED SERVERS DETAILS*******************************"
    pp.pprint(failedServers)
    print "*********************FAILED SERVERS DETAILS*******************************"


def analyzeNetworks(hosts, vlans):
    cliques = findNetworkCliques(hosts, vlans + ['untaged'])
    print "*********************NETWORK CLIQUES*******************************"
    pp = pprint.PrettyPrinter(indent=4)
    for netName, networks in cliques.items():
        pp.pprint("%(name)s - %(networks)s" % dict(name=str(netName), networks=networks))


def printHostsThatFailedInnaguration(failedHosts):
    for hostID, log in failedHosts.items():
        logging.error('Host %(host)s failed innauguration serial log %(log)s', dict(host=hostID, log=log))


def _initializeFastNetworkOnHost(host, vtags):
    logging.info("Init Fast network in host %(host)s", dict(host=host['name']))
    hostToInitialize = host['host']
    testResult = host['result']
    try:
        hostToInitialize.network.initialize()
    except:
        logging.exception("Failed to initialize network")
        pciIdCard = hostToInitialize.network.mellanoxPCIId()
        ethtoolResult = hostToInitialize.network.ethtool()
        lspciOutput = hostToInitialize.ssh.run.script("lspci")
        lsmodOutput = hostToInitialize.ssh.run.script("lsmod")
        if pciIdCard is None:
            testResult.addCheck('net', 'init fast net', False, "Mellanox Card is not identified lspci %(lspci)s lsmod %(lsmod)s"
                                % dict(lspci=lspciOutput, lsmod=lsmodOutput))
        elif hostToInitialize.network.fastInterface() is None:
            testResult.addCheck('net', 'init fast net ', False, "Link is not connected on Mellanox %(ethtool)s"
                                % dict(ethtool=pprint.PrettyPrinter(indent=4).pformat(ethtoolResult)))
        else:
            testResult.addCheck('net', 'init fast net ', False, "Unknown problem lspci %(lspci)s lsmod %(lsmod)s  %(ethtool)s"
                                % dict(lspci=lspciOutput, lsmod=lsmodOutput, ethtool=pprint.PrettyPrinter(indent=4).pformat(ethtoolResult)))
        return False
    try:
        hostToInitialize.network.addTaggedDevices(vtags)
        testResult.addCheck('net', 'init fast net', True)
        return True
    except:
        logging.exception("Failed to Add vtags")
        ifcfgOutput = hostToInitialize.network.ifconfig()
        testResult.addCheck('net', 'init fast net', False, "Failed to add Vports ifcfg %(ifcfg)s" % dict(ifcfg=ifcfgOutput))
        return False


def _initializeFastNetworkOnTestHosts(hosts, vtags):
    jobs = {host['name']: (_initializeFastNetworkOnHost, host, vtags) for host in hosts}
    results = concurrently.run(jobs)

    initializedHosts = [host for host in hosts if results[host['name']]]
    return initializedHosts


def _downloadHostsLogs(hosts):
    try:
        jobs = {host.name: (host.log.prepareAndDownload, '/var/log')
                for host in hosts}
        concurrently.run(jobs, numberOfThreads=10)
    except:
        logging.exception("Failed to dowwnload logs")


def _powerOffServerViaIPMI(hostToPowerOff):
    serverIpmi = ipmi.IPMI(hostToPowerOff['ipmiHost'],
                           hostToPowerOff['ipmiUsername'],
                           hostToPowerOff['ipmiPassword'])
    try:
        serverIpmi._powerCommand('off')
        return True
    except:
        logging.exception("Failed to power off %(host)s" % dict(host=hostToPowerOff['ipmiHost']))
        return False


def _powerOffServers(hosts):
    jobs = {name: (_powerOffServerViaIPMI, hostToPowerOff['props'])
            for name, hostToPowerOff in hosts.items()}
    results = concurrently.run(jobs, numberOfThreads=30)

    sucessfullyPoweredOffHosts = []
    for hostId, result in results.items():
        if not result:
            hosts[hostId]['result'].addCheck('init', 'IPMI power off', False, "Failed to connect via IPMI to %s" % hosts[hostId]['props']['ipmiHost'])
        else:
            hosts[hostId]['result'].addCheck('init', 'IPMI power off', True, '')
            sucessfullyPoweredOffHosts.append(hosts[hostId])
    return sucessfullyPoweredOffHosts


def _createResultsMap(masterHost, hostsToInnagurate):
    hostsMap = {}
    for hostId, host in enumerate(hostsToInnagurate):
        hostsMap[host['hostID']] = {'name': host['hostID'],
                                    'node': node.Node(host['hostID'], masterHost, host['macAddress'], host['ipAddress'], hostId),
                                    'props': host,
                                    'host': None,
                                    'result': servertestresult.ServerTestResult(host['hostID'])}
    return hostsMap


with open(args.rackYaml) as f:
    rackYaml = yaml.load(f)

targetNodes = [n for n in rackYaml['HOSTS'] if n['id'] in args.targetNode]
assert len(targetNodes) == len(args.ipAddress), "Amount of target nodes must be the same as IP`s %d != %d" % (len(targetNodes), len(args.ipAddress))

vtags = args.vlan
label = subprocess.check_output(["solvent", "printlabel", "--thisProject", "--product=rootfs"]).strip()
masterHost = allocateMasterHost(args.rackattackUser, label)
masterHost.network.initialize()
masterHost.network.addTaggedDevices(vtags)
hostsToInnagurate = []

for targetNode, ipAddress in zip(targetNodes, args.ipAddress):
    ipmiHost = socket.gethostbyname(targetNode['ipmiLogin']['hostname'])
    ipmiUsername = targetNode['ipmiLogin']['username']
    ipmiPassword = targetNode['ipmiLogin']['password']
    macAddress = targetNode['primaryMAC']
    hostsToInnagurate.append(dict(hostID=targetNode['id'],
                                  macAddress=macAddress,
                                  ipAddress=ipAddress,
                                  ipmiHost=ipmiHost,
                                  ipmiUsername=ipmiUsername,
                                  ipmiPassword=ipmiPassword))

exitCode = -1
hosts = _createResultsMap(masterHost, hostsToInnagurate)
poweredOnHosts = []
try:
    logging.info("Powering hosts off before start")
    hostsToProced = _powerOffServers(hosts)
    poweredOnHosts = _allocateTestNodesInChunks(masterHost, hostsToProced)

    logging.info('Going to test servers %(names)s',
                 dict(names=' '.join([innaguratedHost['name'] for innaguratedHost in hostsToProced])))

    hostsToProced = _initializeFastNetworkOnTestHosts(poweredOnHosts, vtags)
    if len(hostsToProced) > 0:
        logging.info("Going to check %(servers)d servers", dict(servers=len(hostsToProced)))
        healthchecher.checkServers(masterHost, hostsToProced, vtags)

    exitCode = 0 if len([host for host in hosts.values() if not host['result'].passed()]) == 0 else -1
except:
    logging.exception("Failed running test script")
finally:
    try:
        _downloadHostsLogs([masterHost] + [host['host'] for host in poweredOnHosts])
        printServerResults(hosts)
        analyzeNetworks(poweredOnHosts, vtags)
    finally:
        if args.debug:
            import ipdb
            ipdb.set_trace()
        _powerOffServers(hosts)
    logging.info('PASSED' if exitCode == 0 else 'FAILED')
    sys.exit(exitCode)
