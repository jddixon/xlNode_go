package node

import (
	"crypto/rsa"
	"fmt"
	xi "github.com/jddixon/xlNodeID_go"
	xo "github.com/jddixon/xlOverlay_go"
	xt "github.com/jddixon/xlTransport_go"
	"strings"
	"sync"
	"time"
)

/**
 * A Peer is another Node, a neighbor.
 */

type Peer struct {
	connectors []xt.ConnectorI // to reach the peer
	timeout    int64           // ns from epoch
	contacted  int64           // last contact from this peer, ns from epoch
	up         bool            // set to false if considered unreachable
	mu         sync.Mutex
	BaseNode
}

func NewNewPeer(name string, id *xi.NodeID) (*Peer, error) {
	return NewPeer(name, id, nil, nil, nil, nil)
}

func NewPeer(name string, id *xi.NodeID,
	ck *rsa.PublicKey, sk *rsa.PublicKey,
	o []xo.OverlayI, c []xt.ConnectorI) (p *Peer, err error) {

	baseNode, err := NewBaseNode(name, id, ck, sk, o)

	if err == nil {
		var ctors []xt.ConnectorI // another empty slice
		if c != nil {
			count := len(c)
			for i := 0; i < count; i++ {
				ctors = append(ctors, c[i])
			}
		}
		p = &Peer{
			connectors: ctors,
			BaseNode:   *baseNode,
		}
	}
	return
}

// Given a node, construct a Peer with the same properties.
func NewPeerFromNode(node *Node) (p *Peer, err error) {
	if node == nil {
		err = NilNode
	} else {
		id := node.GetNodeID().Value()
		nodeID, err := xi.New(id)
		if err == nil {
			var o []xo.OverlayI
			for i := 0; i < node.SizeOverlays(); i++ {
				o = append(o, node.GetOverlay(i))
			}
			var ctors []xt.ConnectorI
			for i := 0; i < node.SizeAcceptors(); i++ {
				var ctor *xt.TcpConnector
				ep := node.GetAcceptor(i).GetEndPoint()
				ctor, err = xt.NewTcpConnector(ep)
				if err != nil {
					break
				}
				ctors = append(ctors, ctor)
			}
			if err == nil {
				p, err = NewPeer(node.GetName(), nodeID,
					node.GetCommsPublicKey(), node.GetSigPublicKey(),
					o, ctors)
			}
		}
	}
	return
}

// CONNECTORS ///////////////////////////////////////////////////////
func (p *Peer) AddConnector(c xt.ConnectorI) error {
	if c == nil {
		return NilConnector
	}
	p.connectors = append(p.connectors, c)
	return nil
}

/** @return a count of known Connectors for this Peer */
func (p *Peer) SizeConnectors() int {
	return len(p.connectors)
}

/**
 * Return a Connector, an Address-Protocol pair identifying
 * an Acceptor for the Peer.
 *
 * XXX Could as easily return an EndPoint.
 *
 * @return the Nth Connector
 */
func (p *Peer) GetConnector(n int) xt.ConnectorI {
	return p.connectors[n]
}

// EQUAL ////////////////////////////////////////////////////////////
func (p *Peer) Equal(any interface{}) bool {
	if any == p {
		return true
	}
	if any == nil {
		return false
	}
	switch v := any.(type) {
	case *Peer:
		_ = v
	default:
		return false
	}
	other := any.(*Peer) // type assertion

	// XXX THIS IS A VERY INCOMPLETE IMPLEMENTATION

	return p.BaseNode.Equal(&other.BaseNode)
}

func (p *Peer) Strings() []string {
	ss := []string{"peer {"}
	bns := p.BaseNode.Strings()
	for i := 0; i < len(bns); i++ {
		ss = append(ss, "    "+bns[i])
	}
	ss = append(ss, "    connectors {")
	for i := 0; i < len(p.connectors); i++ {
		ss = append(ss, fmt.Sprintf("        %s", p.connectors[i].String()))
	}
	ss = append(ss, "    }")
	ss = append(ss, "}")
	return ss
}

func (p *Peer) String() string {
	return strings.Join(p.Strings(), "\n")
}

func CollectConnectors(peer *Peer, ss []string) (rest []string, err error) {
	rest = ss
	line := NextNBLine(&rest)
	if line == "connectors {" {
		for {
			line = NextNBLine(&rest)
			if line == "}" {
				break
			}
			var ctor xt.ConnectorI
			ctor, err = xt.ParseConnector(line)
			if err != nil {
				return
			}
			err = peer.AddConnector(ctor)
			if err != nil {
				return
			}
		}
	}
	// if there are no connectors, not a very useful peer
	return
}
func ParsePeer(s string) (peer *Peer, rest []string, err error) {
	ss := strings.Split(s, "\n")
	return ParsePeerFromStrings(ss)
}
func ParsePeerFromStrings(ss []string) (peer *Peer, rest []string, err error) {
	bn, rest, err := ParseBNFromStrings(ss, "peer")
	if err == nil {
		peer = &Peer{BaseNode: *bn}
		rest, err = CollectConnectors(peer, rest)
		line := NextNBLine(&rest)
		if line != "}" {
			err = NotASerializedPeer
		}
	}
	return
}

// LIVENESS /////////////////////////////////////////////////////////

// Return the time (ns from the Epoch) of the last communication with
// this peer.
func (p *Peer) LastContact() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.contacted
}

// A communication with the peer has occurred: mark the time.
func (p *Peer) StillAlive() {
	t := time.Now().UnixNano()
	p.mu.Lock()
	p.contacted = t
	p.mu.Unlock()
}

// Return whether the peer is considered reachable.
func (p *Peer) IsUp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.up
}

// Clear the peer's up flag.  It is no longer considered reachable.
// Return the flag's previous state.
func (p *Peer) MarkDown() (prevState bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prevState = p.up
	p.up = false
	return
}

// Set the peer's up flag.  It is now considered reachable.  Return
// the flag's previous state.
func (p *Peer) MarkUp() (prevState bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prevState = p.up
	p.up = true
	return
}
