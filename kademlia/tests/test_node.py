import random
import hashlib
from struct import pack

from twisted.trial import unittest

from kademlia.node import (
    UnvalidatedNode, ValidatedNode, OwnNode, NodeHeap, NodeValidationError
)
from kademlia.tests.utils import mknode


class NodeTest(unittest.TestCase):
    def test_idSize(self):
        self.assertEqual(len(OwnNode.new().id), 20)

    def test_longID(self):
        rid = mknode().id
        n = UnvalidatedNode(rid)
        self.assertEqual(n.long_id, long(rid.encode('hex'), 16))

    def test_distanceCalculation(self):
        ridone = mknode().id
        ridtwo = mknode().id

        shouldbe = long(ridone.encode('hex'), 16) ^ long(ridtwo.encode('hex'), 16)
        none = UnvalidatedNode(ridone)
        ntwo = UnvalidatedNode(ridtwo)
        self.assertEqual(none.distanceTo(ntwo), shouldbe)

    def test_idValidation(self):
        node = OwnNode.restore(pack('>llllllll', 0, 0, 0 ,0, 0, 0, 0, 15))

        # valid
        challenge = pack('>l', 244)
        response = node.completeChallenge(challenge)
        ValidatedNode(node.id, node.preid, challenge, response)

        # invalid signature raises
        challenge = pack('>l', 244)
        response = pack('>l', 11)
        self.assertRaises(
            NodeValidationError, 
            lambda: ValidatedNode(node.id, node.preid, challenge, response))

        # invalid digest raises
        challenge = pack('>l', 244)
        response = node.completeChallenge(challenge)
        temp = list(node.id)
        temp[0] = 'a'
        node.id = ''.join(temp)
        self.assertRaises(
            NodeValidationError, 
            lambda: ValidatedNode(node.id, node.preid, challenge, response))


class NodeHeapTest(unittest.TestCase):
    def test_maxSize(self):
        n = NodeHeap(mknode(intid=0), 3)
        self.assertEqual(0, len(n))

        for d in range(10):
            n.push(mknode(intid=d))
        self.assertEqual(3, len(n))

        self.assertEqual(3, len(list(n)))

    def test_iteration(self):
        heap = NodeHeap(mknode(intid=0), 5)
        nodes = [mknode(intid=x) for x in range(10)]
        for index, node in enumerate(nodes):
            heap.push(node)
        for index, node in enumerate(heap):
            self.assertEqual(index, node.long_id)
            self.assertTrue(index < 5)

    def test_remove(self):
        heap = NodeHeap(mknode(intid=0), 5)
        nodes = [mknode(intid=x) for x in range(10)]
        for node in nodes:
            heap.push(node)

        heap.remove([nodes[0].id, nodes[1].id])
        self.assertEqual(len(list(heap)), 5)
        for index, node in enumerate(heap):
            self.assertEqual(index + 2, node.long_id)
            self.assertTrue(index < 5)
