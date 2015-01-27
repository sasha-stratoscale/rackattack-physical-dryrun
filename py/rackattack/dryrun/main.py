import logging
import paramiko
from strato.common.log import configurelogging
import pprint
import sys
from rackattack.dryrun import servertestresult
import traceback
configurelogging.configureLogging('dryrun')
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
parser.add_argument("--debug", default=False, type=bool)

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
    failedNodes, log = masterHost.seed.runCallable(innaugurator.innaugurate,
                                                   osmosisServerIP=args.osmosisServerIP,
                                                   rootfsLabel=label,
                                                   nodesToInnagurate=hostsToInnagurate)
    if len(failedNodes) > 0:
        logging.error("Failed to innagurate %(nodes)d nodes log %(log)s", dict(nodes=len(failedNodes), log=log))
    for hostId, host in enumerate(hostsToInnagurate):
        if host['hostID'] in failedNodes:
            continue
        allocatedNode = node.Node(host['hostID'], masterHost, host['macAddress'], host['ipAddress'], hostId)
        hostToCheck = dryrunhost.DryRunHost(allocatedNode, dict(username='root', password='dryrun'))
        hostToCheck.ssh.connect()
        logging.info("Sucessfully connected to node %(node)s", dict(node=hostToCheck.name))
        innaguratedHosts.append(hostToCheck)
    return (innaguratedHosts, failedNodes)


def printServerResults(results):
    passedServers = [result for result in results if result.passed()]
    failedServers = [result for result in result if not result.passed()]
    print "TOTALLY %d PASSED %d FAILED" % (len(passedServers), len(failedServers))

    print "*********************FAILED SERVERS*******************************"
    pp = pprint.PrettyPrinter(indent=4)
    for server in failedServers:
        pp.pprint("%(name) - %(summary)s" % dict(name=server['name'], summary=server['summary']))
    print "*********************FAILED SERVERS DETAILS*******************************"
    pp.pprint(failedServers)
    print "*********************FAILED SERVERS DETAILS*******************************"


def printHostsThatFailedInnaguration(failedHosts):
    for hostID, log in failedHosts.items():
        logging.error('Host %(host)s failed innauguration serial log %(log)s', dict(host=hostID, log=log))


def _initializeFastNetworkOnHost(hostToInitialize, vtags, testResult):
    logging.info("Init Fast network in host %(host)s", dict(host=hostToInitialize.name))
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


def _initializeFastNetworkOnTestHosts(hostsMap, vtags):
    jobs = {host: (_initializeFastNetworkOnHost, host, vtags, testResult)
            for host, testResult in hostsMap.items()}
    results = concurrently.run(jobs)

    initializedHosts = {resultHost: hostsMap[resultHost] for resultHost, result in results.items() if result}
    return initializedHosts

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
innaguratedHosts = []
testResults = []
exitCode = -1
try:
    innaguratedHosts, failedHosts = _allocateTestNodes(masterHost, hostsToInnagurate)
    for failedHost, log in failedHosts.items():
        testResult = servertestresult.ServerTestResult(failedHost)
        testResult.addCheck('init', 'innaugarate', False, log)
        testResults.append(testResult)

    logging.info('Going to test servers %(names)s',
                 dict(names=' '.join([innaguratedHost.name for innaguratedHost in innaguratedHosts])))

    hostsResultsMap = {innaguratedHost: servertestresult.ServerTestResult(innaguratedHost.name)
                       for innaguratedHost in innaguratedHosts}
    testResults.extend(hostsResultsMap.values())
    hostsToRunCheckOnMap = _initializeFastNetworkOnTestHosts(hostsResultsMap, vtags)
    if len(hostsToRunCheckOnMap) > 0:
        healthchecher.checkServers(masterHost, hostsToRunCheckOnMap, vtags)
    exitCode = 0 if len([testResult for testResult in testResults if not testResult.passed()]) == 0 else -1
except:
    logging.exception("Failed running test script")
finally:
    printServerResults(testResults)
    if args.debug:
        import ipdb
        ipdb.set_trace()
    if len(innaguratedHosts) > 0:
        logging.info("Powering hosts off")
        jobs = {innaguratedHost.name: (ipmi.IPMI(ipmiHost, ipmiUsername, ipmiPassword)._powerCommand, 'off')
                for innaguratedHost in innaguratedHosts}
        concurrently.run(jobs)
    logging.info('PASSED' if exitCode == 0 else 'FAILED')
    sys.exit(exitCode)
