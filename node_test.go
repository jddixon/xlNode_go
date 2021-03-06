package node

import (
	cr "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xc "github.com/jddixon/xlCrypto_go"
	xi "github.com/jddixon/xlNodeID_go"
	xt "github.com/jddixon/xlTransport_go"
	xu "github.com/jddixon/xlUtil_go"
	. "gopkg.in/check.v1"
	"runtime"
	"strings"
	//"time"
)

const (
	VERBOSITY = 1
)

var (
	MY_MAX_PROC = 2 // should be OK for test, a 2-core machine
)

func makeNodeID(rng *xr.PRNG) (*xi.NodeID, error) {
	var buffer []byte
	// quasi-random choice, whether to use an SHA1 or SHA3 nodeID
	if rng.NextBoolean() {
		buffer = make([]byte, xu.SHA1_BIN_LEN)
	} else {
		buffer = make([]byte, xu.SHA3_BIN_LEN)
	}
	rng.NextBytes(buffer)
	return xi.NewNodeID(buffer)
}

func (s *XLSuite) doKeyTests(c *C, node *Node, rng *xr.PRNG) {
	// COMMS KEY
	commsPubKey := node.GetCommsPublicKey()
	c.Assert(commsPubKey, Not(IsNil)) // NOT

	privCommsKey := node.GetCommsPrivateKey()
	c.Assert(privCommsKey.Validate(), IsNil)

	expLen := (*privCommsKey.D).BitLen()
	if VERBOSITY > 1 {
		fmt.Printf("bit length of comms private key exponent is %d\n", expLen)
	}
	// 2037 seen at least once
	c.Assert(true, Equals, (2036 <= expLen) && (expLen <= 2048))

	c.Assert(privCommsKey.PublicKey, Equals, *commsPubKey) // XXX FAILS

	// SIG KEY
	sigPubKey := node.GetSigPublicKey()
	c.Assert(sigPubKey, Not(IsNil)) // NOT

	privSigKey := node.GetSigPrivateKey()
	c.Assert(privSigKey.Validate(), IsNil)

	expLen = (*privSigKey.D).BitLen()
	if VERBOSITY > 1 {
		fmt.Printf("bit length of sig private key exponent is %d\n", expLen)
	}
	// lowest value seen as of 2013-07-16 was 2039
	c.Assert(true, Equals, (2036 <= expLen) && (expLen <= 2048))

	c.Assert(privSigKey.PublicKey, Equals, *sigPubKey) // FOO

	// sign /////////////////////////////////////////////////////////
	msgLen := 128
	msg := make([]byte, msgLen)
	rng.NextBytes(msg)

	d := sha1.New()
	d.Write(msg)
	hash := d.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, node.skPriv, cr.SHA1, hash)
	c.Assert(err, IsNil)

	signer := node.getSigner()
	signer.Update(msg)
	sig2, err := signer.Sign() // XXX change interface to allow arg

	lenSig := len(sig)
	lenSig2 := len(sig2)
	c.Assert(lenSig, Equals, lenSig2)

	for i := 0; i < lenSig; i++ {
		c.Assert(sig[i], Equals, sig2[i])
	}

	// verify ///////////////////////////////////////////////////////
	err = rsa.VerifyPKCS1v15(sigPubKey, cr.SHA1, hash, sig)
	c.Assert(err, IsNil)

	// 2013-06-15, SigVerify now returns error, so nil means OK
	c.Assert(nil, Equals, xc.SigVerify(sigPubKey, msg, sig))

	s.nilArgCheck(c)
}

// XXX TODO: move these tests into crypto/sig_test.go
// func nilArgCheck(t *testing.T) {
func (s *XLSuite) nilArgCheck(c *C) {
	// the next statement should always return an error
	err := xc.SigVerify(nil, nil, nil)
	c.Assert(nil, Not(Equals), err)
}

// END OF TODO

func (s *XLSuite) TestRuntime(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_RUN_TIME")
	}
	if VERBOSITY > 1 {
		MY_MAX_PROC = runtime.NumCPU()
		was := runtime.GOMAXPROCS(MY_MAX_PROC)
		fmt.Printf("GOMAXPROCS was %d, has been reset to %d\n",
			was, MY_MAX_PROC)
		fmt.Printf("Number of CPUs: %d\n", runtime.NumCPU())
	}
}

func (s *XLSuite) TestNewConstructor(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_NEW_CONSTRUCTOR")
	}
	// if  constructor assigns a nil NodeID, we should get an
	// IllegalArgument panic
	// XXX STUB

	// if assigned a nil key, the New constructor should panic
	// with an IllegalArgument string
	// XXX STUB

}

func (s *XLSuite) shouldCreateTcpEndPoint(c *C, addr string) *xt.TcpEndPoint {
	ep, err := xt.NewTcpEndPoint(addr)
	c.Assert(err, Equals, nil)
	c.Assert(ep, Not(Equals), nil)
	return ep
}
func (s *XLSuite) TestAutoCreateOverlays(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_AUTO_CREATE_OVERLAYS")
	}
	MY_MAX_PROC = runtime.NumCPU()
	was := runtime.GOMAXPROCS(MY_MAX_PROC)
	if VERBOSITY > 1 {
		fmt.Printf("GOMAXPROCS was %d, has been reset to %d\n",
			was, MY_MAX_PROC)
	}
	rng := xr.MakeSimpleRNG()
	name := rng.NextFileName(4)
	id, err := makeNodeID(rng)
	c.Assert(err, Equals, nil)
	c.Assert(id, Not(IsNil))

	ep0 := s.shouldCreateTcpEndPoint(c, "127.0.0.0:0")
	ep1 := s.shouldCreateTcpEndPoint(c, "127.0.0.0:0")
	ep2 := s.shouldCreateTcpEndPoint(c, "127.0.0.0:0")
	e := []xt.EndPointI{ep0, ep1, ep2}

	lfs := "tmp/" + hex.EncodeToString(id.Value())
	n, err := New(name, id, lfs, nil, nil, nil, e, nil)
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)
	defer n.CloseAcc()

	c.Assert(n.SizeEndPoints(), Equals, len(e))
	c.Assert(n.SizeOverlays(), Equals, 1)

	// expect to find an acceptor for each endpoint
	// XXX STUB XXX

	// CloseAcc must close all three acceptors
	// XXX STUB XXX

}

// Return an initialized and tested host, with a NodeID, ckPriv,
// and skPriv.  OpenAcc() is not called and so any acceptors are not open.
func (s *XLSuite) makeHost(c *C, rng *xr.PRNG) *Node {
	// XXX names may not be unique
	name := rng.NextFileName(6)
	for {
		first := string(name[0])
		if !strings.Contains(first, "0123456789") &&
			!strings.Contains(name, "-") {
			break
		}
		name = rng.NextFileName(6)
	}
	id, err := makeNodeID(rng)
	c.Assert(err, Equals, nil)
	c.Assert(id, Not(IsNil))

	lfs := "tmp/" + hex.EncodeToString(id.Value())
	n, err := NewNew(name, id, lfs)
	c.Assert(err, IsNil)
	c.Assert(n, Not(IsNil))
	c.Assert(name, Equals, n.GetName())
	actualID := n.GetNodeID()
	c.Assert(true, Equals, id.Equal(actualID))
	s.doKeyTests(c, n, rng)
	c.Assert(0, Equals, (*n).SizePeers())
	c.Assert(0, Equals, (*n).SizeOverlays())
	c.Assert(0, Equals, n.SizeConnections())
	c.Assert(lfs, Equals, n.GetLFS())
	return n
}

// Create a Peer from information in the Node passed.  Endpoints
// (and so Overlays) must have already been added to the Node.
func (s *XLSuite) peerFromHost(c *C, n *Node) (peer *Peer) {
	var err error
	k := len(n.endPoints)
	ctors := make([]xt.ConnectorI, k)
	for i := 0; i < k; i++ {
		ctors[i], err = xt.NewTcpConnector(n.GetEndPoint(i))
		c.Assert(err, Equals, nil)
	}
	peer = &Peer{connectors: ctors, BaseNode: n.BaseNode}
	//peer.commsPubKey =  n.GetCommsPublicKey()
	//peer.sigPubKey	 =  n.GetSigPublicKey()

	return peer
}

// Creates a local (127.0.0.1) endPoint and adds it to the node.
func (s *XLSuite) makeAnEndPoint(c *C, node *Node) {
	addr := fmt.Sprintf("127.0.0.1:0")
	ep, err := xt.NewTcpEndPoint(addr)
	c.Assert(err, IsNil)
	c.Assert(ep, Not(IsNil))
	ndx, err := node.AddEndPoint(ep)
	c.Assert(err, IsNil)
	c.Assert(ndx, Equals, 0) // it's the only one
}
func (s *XLSuite) TestNodeSerialization(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_NODE_SERIALIZATION")
	}
	if VERBOSITY > 1 {
		was := runtime.GOMAXPROCS(MY_MAX_PROC)
		fmt.Printf("GOMAXPROCS was %d, has been reset to %d\n",
			was, MY_MAX_PROC)
	}
	rng := xr.MakeSimpleRNG()

	node := s.makeHost(c, rng)
	s.makeAnEndPoint(c, node)

	// SEGUE I: TEST Get/setLFS()
	currentLFS := node.GetLFS()

	// This does not follow our standard practice of using the nodeID
	// as the name of the local file system directory.
	lfs := "tmp/" + rng.NextFileName(4)
	err := node.setLFS(lfs)
	c.Assert(err, IsNil)
	c.Assert(node.GetLFS(), Equals, lfs)

	// restore old LFS
	err = node.setLFS(currentLFS)
	c.Assert(err, IsNil)
	c.Assert(node.GetLFS(), Equals, currentLFS)

	err = node.OpenAcc()
	c.Assert(err, IsNil)
	defer node.CloseAcc() // any error ignored

	const K = 3
	peers := make([]*Peer, K)

	for i := 0; i < K; i++ {
		host := s.makeHost(c, rng)
		s.makeAnEndPoint(c, host)
		peers[i] = s.peerFromHost(c, host)
		ndx, err := node.AddPeer(peers[i])
		c.Assert(err, IsNil)
		c.Assert(ndx, Equals, i)
	}
	// we now have a node with K peers
	serialized := node.String()

	// SEGUE II: verify that FindPeer works
	for i := 0; i < K; i++ {
		id := peers[i].GetNodeID().Value()
		p, err := node.FindPeer(id)
		c.Assert(err, IsNil)
		c.Assert(p, Not(IsNil))
		c.Assert(p.Equal(peers[i]), Equals, true)
	}
	// closes all acceptors
	err = node.CloseAcc()
	c.Assert(err, IsNil)
	c.Assert(node.running, Equals, false)

	// XXX parse succeeds if we sleep 100ms, fails if we sleep 10ms
	// time.Sleep(70 * time.Millisecond)

	// DEBUG
	fmt.Printf("SERIALIZED:\n%s\n", serialized)
	// END

	backAgain, rest, err := Parse(serialized)
	c.Assert(err, IsNil)
	c.Assert(len(rest), Equals, 0)
	c.Assert(backAgain.running, Equals, false)

	err = backAgain.OpenAcc()
	c.Assert(err, IsNil)
	defer backAgain.CloseAcc()

	reserialized := backAgain.String()
	c.Assert(reserialized, Equals, serialized)
}
