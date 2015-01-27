import netifaces
import re
import subprocess
import socket


def _exec(command):
    return subprocess.check_output(command, shell=True, stdin=open('/dev/null'), close_fds=True)


def configureStaticIPOnDevice(ip4Network, deviceName):
    _exec('ip addr add %(ipmask)s dev %(deviceName)s' % dict(ipmask=ip4Network.with_prefixlen, deviceName=deviceName))


def interfaces():
    nicsBySpeed = dict(slow=[], fast=[])
    # This is copied fron postinstaller
    nics = [nic for nic in netifaces.interfaces() if nic.startswith('e') or nic.startswith('p')]

    for nic in nics:
        ethtoolOutput = _exec('ethtool %s' % nic).split('\n\t')
        speedString = ''.join([ethtoolLine for ethtoolLine in ethtoolOutput if ethtoolLine.startswith('Speed')])
        if not speedString or speedString == 'Speed: Unknown!':
            continue
        else:
            speed = int(re.findall(r'\d+', speedString)[0])
        speedKey = 'fast' if speed > 1000 else 'slow'
        macAddress = netifaces.ifaddresses(nic)[netifaces.AF_LINK][0]['addr']
        nicsBySpeed[speedKey].append((nic, speed, macAddress))
    return nicsBySpeed


def ethtool():
    return {nic: _exec('ethtool %s' % nic) for nic in netifaces.interfaces()
            if nic.startswith('e') or nic.startswith('p')}


def myIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 1000))
        return s.getsockname()[0]
    finally:
        s.close()


def netmask():
    output = subprocess.check_output(['ifconfig'])
    return re.search(r"inet\s+%s\s+netmask\s+(\S+)\s" % myIP(), output).group(1)


def gateway():
    output = subprocess.check_output(['ip', 'route', 'show'])
    return re.search(r"default\s+via\s+(\S+)\s", output).group(1)


def dropFirewall():
    subprocess.check_output(["iptables", "--flush"])
    subprocess.check_output(["iptables", '-t', 'nat', "--flush"])
    subprocess.check_output(["iptables", "--delete-chain"])
    subprocess.check_output(["iptables", '-t', 'nat', "--delete-chain"])
