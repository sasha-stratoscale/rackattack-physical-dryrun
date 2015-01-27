from rackattack import api


class Node(api.Node):

    def __init__(self, name, masterHost, macAddress, ipAddress, nodeId):
        self._ipAddress = ipAddress
        self.masterHost = masterHost
        self._name = name
        self.nodeId = nodeId
        self._primaryMacAddress = macAddress

    def ipAddress(self):
        return self._ipAddress

    def name(self):
        return self._name

    def id(self):
        return self.nodeId

    def primaryMACAddress(self):
        return self._primaryMacAddress
