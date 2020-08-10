package mmdbwriter

import (
	"net"

	"github.com/pkg/errors"
)

type recordType byte

const (
	recordTypeEmpty recordType = iota
	recordTypeData
	recordTypeNode
	recordTypeAlias
	recordTypeFixedNode
	recordTypeReserved
)

type record struct {
	node       *node
	value      DataType
	recordType recordType
}

// each node contains two records.
type node struct {
	children [2]record
	nodeNum  int
}

func (n *node) insert(
	ip net.IP,
	prefixLen int,
	recordType recordType,
	value DataType,
	insertedNode *node,
	currentDepth int,
) error {
	newDepth := currentDepth + 1
	// Check if we are inside the network already
	if newDepth > prefixLen {
		// Data already exists for the network so insert into all the children.
		// We will prune duplicate nodes when we finalize.
		err := n.children[0].insert(ip, prefixLen, recordType, value, insertedNode, newDepth)
		if err != nil {
			return err
		}
		return n.children[1].insert(ip, prefixLen, recordType, value, insertedNode, newDepth)
	}

	// We haven't reached the network yet.
	pos := bitAt(ip, currentDepth)
	r := &n.children[pos]
	return r.insert(ip, prefixLen, recordType, value, insertedNode, newDepth)
}

func (r *record) insert(
	ip net.IP,
	prefixLen int,
	recordType recordType,
	value DataType,
	insertedNode *node,
	newDepth int,
) error {
	switch r.recordType {
	case recordTypeNode, recordTypeFixedNode:
	case recordTypeEmpty, recordTypeData:
		// When we add record merging support, it should go here.
		if newDepth >= prefixLen {
			r.node = insertedNode
			r.value = value
			r.recordType = recordType
			return nil
		}

		// We are splitting this record so we create two duplicate child
		// records.
		r.node = &node{children: [2]record{*r, *r}}
		r.value = nil
		r.recordType = recordTypeNode
	case recordTypeReserved:
		if prefixLen >= newDepth {
			return errors.Errorf(
				"attempt to insert %s/%d, which is in a reserved network",
				ip,
				prefixLen,
			)
		}
		// If we are inserting a network that contains a reserved network,
		// we silently remove the reserved network.
		return nil
	case recordTypeAlias:
		if prefixLen < newDepth {
			// Do nothing. We are inserting a network that contains an aliased
			// network. We silently ignore.
			return nil
		}
		// attempting to insert _into_ an aliased network
		return errors.Errorf(
			"attempt to insert %s/%d, which is in an aliased network",
			ip,
			prefixLen,
		)
	default:
		return errors.Errorf("inserting into record type %d not implemented!", r.recordType)
	}

	return r.node.insert(ip, prefixLen, recordType, value, insertedNode, newDepth)
}

func (n *node) get(
	ip net.IP,
	depth int,
) (int, record) {
	r := n.children[bitAt(ip, depth)]

	depth++

	switch r.recordType {
	case recordTypeNode, recordTypeAlias, recordTypeFixedNode:
		return r.node.get(ip, depth)
	default:
		return depth, r
	}
}

// finalize current just returns the node count. However, it will prune the
// tree eventually.
func (n *node) finalize(currentNum int) int {
	n.nodeNum = currentNum
	currentNum++

	if n.children[0].recordType == recordTypeNode ||
		n.children[0].recordType == recordTypeFixedNode {
		currentNum = n.children[0].node.finalize(currentNum)
	}

	if n.children[1].recordType == recordTypeNode ||
		n.children[1].recordType == recordTypeFixedNode {
		currentNum = n.children[1].node.finalize(currentNum)
	}
	return currentNum
}

func bitAt(ip net.IP, depth int) byte {
	return (ip[depth/8] >> (7 - (depth % 8))) & 1
}
