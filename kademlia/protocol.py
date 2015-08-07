import random

from twisted.internet import defer

from rpcudp.protocol import RPCProtocol

from kademlia.node import (
    ValidatedNode, UnvalidatedNode, NodeValidationError, format_nodeid
)
from kademlia.routing import RoutingTable
from kademlia.log import Logger
from kademlia.utils import digest

class KademliaProtocol(RPCProtocol):
    def __init__(self, sourceNode, storage, ksize):
        RPCProtocol.__init__(self)
        self.router = RoutingTable(self, ksize, sourceNode)
        self.storage = storage
        self.sourceNode = sourceNode
        self.log = Logger(system=self)

    def getRefreshIDs(self):
        """
        Get ids to search for to keep old buckets up to date.
        """
        ids = []
        for bucket in self.router.getLonelyBuckets():
            ids.append(random.randint(*bucket.range))
        return ids

    def rpc_stun(self, sender):
        return sender

    def _addContact(self, sender, nodeid, nodepreid):
        def confirm(sender, challengeResponse):
            details = nodeid, nodepreid, sender[0], sender[1]
            if not self.router.isNewNode(UnvalidatedNode(nodeid[0])):
                return False
            try:
                source = ValidatedNode(*details)
                self.router.addContact(source)
                return True
            except NodeValidationError as e:
                self.log.warning(e)
                return False
        return self.challenge(sender, self.sourceNode.getChallenge()).addCallback(confirm)

    def rpc_challenge(self, sender, challenge):
        return self.sourceNode.completeChallenge(challenge)

    def rpc_ping(self, sender, nodeid, nodepreid, challenge):
        self._addContact(sender, nodeid, nodepreid)
        return (
            self.sourceNode.id, 
            self.sourceNode.preid, 
            self.sourceNode.completeChallenge(challenge),
        )

    def rpc_store(self, sender, nodeid, nodepreid, key, value):
        d = self._addContact(sender, nodeid, nodepreid)
        def store(source):
            if not source:
                return
            self.log.debug("got a store request from %s, storing value" % str(sender))
            self.storage[key] = value
        d.addCallback(store)
        return True

    def rpc_find_node(self, sender, nodeid, nodepreid, key):
        self.log.info("finding neighbors of {} in local table".format(format_nodeid(nodeid)))
        self._addContact(sender, nodeid, nodepreid)
        node = UnvalidatedNode(key)
        return map(tuple, self.router.findNeighbors(node, exclude=UnvalidatedNode(nodeid)))

    def rpc_find_value(self, sender, nodeid, nodepreid, key):
        self._addContact(sender, nodeid, nodepreid)
        value = self.storage.get(key, None)
        if value is None:
            return self.rpc_find_node(sender, nodeid, nodepreid, key)
        return { 'value': value }

    def callFindNode(self, nodeToAsk, nodeToFind):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.find_node(address, self.sourceNode.id, self.sourceNode.preid, nodeToFind.id)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callFindValue(self, nodeToAsk, nodeToFind):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.find_value(address, self.sourceNode.id, self.sourceNode.preid, nodeToFind.id)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callPing(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.ping(address, self.sourceNode.id, self.sourceNode.preid, self.sourceNode.generateChallenge())
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callStore(self, nodeToAsk, key, value):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.store(address, self.sourceNode.id, self.sourceNode.preid, key, value)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def transferKeyValues(self, node):
        """
        Given a new node, send it all the keys/values it should be storing.

        @param node: A new node that just joined (or that we just found out
        about).

        Process:
        For each key in storage, get k closest nodes.  If newnode is closer
        than the furtherst in that list, and the node for this server
        is closer than the closest in that list, then store the key/value
        on the new node (per section 2.5 of the paper)
        """
        ds = []
        for key, value in self.storage.iteritems():
            keynode = UnvalidatedNode(digest(key))
            neighbors = self.router.findNeighbors(keynode)
            if len(neighbors) > 0:
                newNodeClose = node.distanceTo(keynode) < neighbors[-1].distanceTo(keynode)
                thisNodeClosest = self.sourceNode.distanceTo(keynode) < neighbors[0].distanceTo(keynode)
            if len(neighbors) == 0 or (newNodeClose and thisNodeClosest):
                ds.append(self.callStore(node, key, value))
        return defer.gatherResults(ds)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            self.log.info("got response from %s, adding to router" % node)
            self.router.addContact(node)
            if self.router.isNewNode(node):
                self.transferKeyValues(node)
        else:
            self.log.debug("no response from %s, removing from router" % node)
            self.router.removeContact(node)
        return result
