package node

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xi "github.com/jddixon/xlNodeID_go"
	xo "github.com/jddixon/xlOverlay_go"
	xt "github.com/jddixon/xlTransport_go"
	xu "github.com/jddixon/xlUtil_go"
)

var _ = fmt.Print

func MockLocalHostCluster(K int) (nodes []*Node, accs []*xt.TcpAcceptor) {

	rng := xr.MakeSimpleRNG()

	// Create K nodes, each with a NodeID, two RSA private keys (sig and
	// comms), and two RSA public keys.  Each node creates a TcpAcceptor
	// running on 127.0.0.1 and a random (= system-supplied) port.
	names := make([]string, K)
	nodeIDs := make([]*xi.NodeID, K)
	for i := 0; i < K; i++ {
		// TODO: MAKE NAMES UNIQUE
		names[i] = rng.NextFileName(4)
		val := make([]byte, xu.SHA1_BIN_LEN)
		rng.NextBytes(val)
		nodeIDs[i], _ = xi.NewNodeID(val)
	}
	nodes = make([]*Node, K)
	accs = make([]*xt.TcpAcceptor, K)
	accEndPoints := make([]*xt.TcpEndPoint, K)
	for i := 0; i < K; i++ {
		lfs := "tmp/" + hex.EncodeToString(nodeIDs[i].Value())
		nodes[i], _ = NewNew(names[i], nodeIDs[i], lfs)
	}
	// XXX We need this functionality in using code
	//	defer func() {
	//		for i := 0; i < K; i++ {
	//			if accs[i] != nil {
	//				accs[i].CloseAcc()
	//			}
	//		}
	//	}()

	// Collect the nodeID, public keys, and listening address from each
	// node.

	// all nodes on the same overlay
	ar, _ := xo.NewCIDRAddrRange("127.0.0.0/8")
	overlay, _ := xo.NewIPOverlay("XO", ar, "tcp", 1.0)

	// add an endpoint to each node
	for i := 0; i < K; i++ {
		ep, _ := xt.NewTcpEndPoint("127.0.0.1:0")
		nodes[i].AddEndPoint(ep)
		nodes[i].OpenAcc() // XXX POSSIBLE ERRORS IGNORED
		accs[i] = nodes[i].GetAcceptor(0).(*xt.TcpAcceptor)
		accEndPoints[i] = accs[i].GetEndPoint().(*xt.TcpEndPoint)
	}

	ckPrivs := make([]*rsa.PublicKey, K)
	skPrivs := make([]*rsa.PublicKey, K)
	ctors := make([]*xt.TcpConnector, K)

	for i := 0; i < K; i++ {
		// we already have nodeIDs
		ckPrivs[i] = nodes[i].GetCommsPublicKey()
		skPrivs[i] = nodes[i].GetSigPublicKey()
		ctors[i], _ = xt.NewTcpConnector(accEndPoints[i])
	}

	overlaySlice := []xo.OverlayI{overlay}
	peers := make([]*Peer, K)
	for i := 0; i < K; i++ {
		ctorSlice := []xt.ConnectorI{ctors[i]}
		_ = ctorSlice
		peers[i], _ = NewPeer(names[i], nodeIDs[i], ckPrivs[i], skPrivs[i],
			overlaySlice, ctorSlice)
	}

	// Use the information collected to configure each node.
	for i := 0; i < K; i++ {
		for j := 0; j < K; j++ {
			if i != j {
				nodes[i].AddPeer(peers[j])
			}
		}
	}
	return
}
