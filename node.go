package node

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	xc "github.com/jddixon/xlCrypto_go"
	xi "github.com/jddixon/xlNodeID_go"
	xo "github.com/jddixon/xlOverlay_go"
	xt "github.com/jddixon/xlTransport_go"
	xf "github.com/jddixon/xlUtil_go/lfs"
	"hash"
	"strings"
	"sync"
)

var _ = fmt.Print

// A Node is uniquely identified by a NodeID and can satisfy an
// identity test constructed using its public key.  That is, it
// can prove that it holds the private key materials corresponding
// to the public key..
//
type Node struct {
	lfs         string
	ckPriv      *rsa.PrivateKey
	skPriv      *rsa.PrivateKey
	endPoints   []xt.EndPointI
	acceptors   []xt.AcceptorI // volatile, do not serialize
	peers       []*Peer
	connections []xt.ConnectionI // volatile
	gateways    []Gateway
	peerMap     *xi.IDMap
	running     bool
	mu          sync.Mutex
	BaseNode    // listed last, but serialize first
}

func NewNew(name string, id *xi.NodeID, lfs string) (*Node, error) {
	// XXX create default 2K bit RSA key
	return New(name, id, lfs, nil, nil, nil, nil, nil)
}

// XXX Creating a Node with a list of live connections seems nonsensical.
func New(name string, id *xi.NodeID, lfs string,
	ckPriv, skPriv *rsa.PrivateKey,
	o []xo.OverlayI, e []xt.EndPointI, p []*Peer) (n *Node, err error) {

	// lfs should be a well-formed POSIX path; if the directory does
	// not exist we should create it.
	err = xf.CheckLFS(lfs, 0700)

	// The ckPriv is an RSA key used to encrypt short messages.
	if err == nil {
		if ckPriv == nil {
			ckPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		}
		if err == nil {
			// The skPriv is an RSA key used to create digital signatures.
			if skPriv == nil {
				skPriv, err = rsa.GenerateKey(rand.Reader, 2048)
			}
		}
	}
	// The node communicates through its endpoints.  These are
	// contained in overlays.  If an endpoint in 127.0.0.0/8
	// is in the list of endpoints, that overlay is automatically
	// added to the list of overlays with the name "localhost".
	// Other IPv4 endpoints are assumed to be in 0.0.0.0/0
	// ("globalV4") unless there is another containing overlay
	// except that endpoints in private address space are treated
	// differently.  Unless there is an overlay with a containing
	// address space, addresses in 10/8 are assigned to "privateA",
	// addresses in 172.16/12 are assigned to "privateB", and
	// any in 192.168/16 are assigned to "privateC".  All of these
	// overlays are automatically created unless there is a
	// pre-existing overlay whose address range is the same as one
	// of these are contained within one of them.

	var (
		endPoints []xt.EndPointI
		acceptors []xt.AcceptorI // each must share index with endPoint
		overlays  []xo.OverlayI
		m         *xi.IDMap
		peers     []*Peer // an empty slice
	)

	if err == nil {
		m, err = xi.NewNewIDMap()
	}
	if err == nil {
		if p != nil {
			count := len(p)
			for i := 0; i < count; i++ {
				err = m.Insert(p[i].GetNodeID().Value(), &p[i])
				if err != nil {
					break
				}
				peers = append(peers, p[i])
			}
		}
	}
	if err == nil {
		commsPubKey := &(*ckPriv).PublicKey
		sigPubKey := &(*skPriv).PublicKey

		var baseNode *BaseNode
		baseNode, err = NewBaseNode(name, id, commsPubKey, sigPubKey, overlays)
		if err == nil {
			n = &Node{ckPriv: ckPriv,
				skPriv:    skPriv,
				acceptors: acceptors,
				endPoints: endPoints,
				peers:     peers,
				gateways:  nil,
				lfs:       lfs,
				peerMap:   m,
				BaseNode:  *baseNode}
			if err == nil {
				if o != nil {
					count := len(o)
					for i := 0; i < count; i++ {
						overlays = append(overlays, o[i])
					}
				}
				if e != nil {
					count := len(e)
					for i := 0; i < count; i++ {
						// _, err = addEndPoint(e[i], &endPoints, &acceptors, &overlays)
						_, err = n.AddEndPoint(e[i])
					}
				}
			}
		}
	}
	return
}

// ENDPOINTS ////////////////////////////////////////////////////////

/**
 * Add an endPoint to a node and open an acceptor.  If a compatible
 * overlay does not exist, add the default for the endPoint.
 */
func (n *Node) AddEndPoint(e xt.EndPointI) (ndx int, err error) {
	if e == nil {
		return -1, NilEndPoint
	}
	ndx = -1
	foundOverlay := false
	count := len(n.overlays)
	if count > 0 {
		for j := 0; j < count; j++ {
			overlay := (n.overlays)[j]
			if overlay.IsElement(e) {
				foundOverlay = true
				break
			}
		}
	}
	if !foundOverlay {
		// create a suitable overlay
		var newO xo.OverlayI
		newO, err = xo.DefaultOverlay(e)
		if err != nil {
			return
		}
		// add it to our collection
		n.overlays = append(n.overlays, newO)
	}
	if ndx == -1 {
		n.endPoints = append(n.endPoints, e)
		ndx = len(n.endPoints) - 1
	}
	return
}

// Return a count of the number of endPoints the peer can be accessed through
func (n *Node) SizeEndPoints() int {
	return len(n.endPoints)
}

func (n *Node) GetEndPoint(x int) xt.EndPointI {
	return n.endPoints[x]
}

// ACCEPTORS ////////////////////////////////////////////////////////
// no accAcceptor() function; add the endPoint instead

// Return a count of the number of acceptors the node listens on
func (n *Node) SizeAcceptors() int {
	return len(n.acceptors)
}

// Return the Nth acceptor, should it exist, or nil.
func (n *Node) GetAcceptor(x int) (acc xt.AcceptorI) {
	if x >= 0 && x < len(n.acceptors) {
		acc = n.acceptors[x]
	}
	return
}

// RUN() ////////////////////////////////////////////////////////////

/**
 * Do whatever is necessary to transition a Node to the running state;
 * in particular, open all acceptors.
 */
func (n *Node) OpenAcc() (err error) {

	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running {
		// XXX STUB
		n.running = true

		count := len(n.endPoints)
		if count > 0 {
			for i := 0; err == nil && i < count; i++ {
				var acc *xt.TcpAcceptor
				e := n.endPoints[i]
				// DEBUG
				//fmt.Printf("OpenAcc: endPoint %d is %s\n", i, e.String())
				// END
				if e.Transport() == "tcp" {
					// XXX HACK ON ADDRESS
					strAddr := e.String()[13:]
					unBound := strings.HasSuffix(strAddr, ":0")
					acc, err = xt.NewTcpAcceptor(strAddr)
					if err == nil && unBound {
						// DEBUG
						//fmt.Printf("BINDING endPoint %d\n", i)
						// END
						strAddr = acc.String()[26:]
						n.endPoints[i], err = xt.NewTcpEndPoint(strAddr)
					}
					// DEBUG
					//fmt.Printf("OpenAcc: acceptor %d is %s\n", i, acc.String())
					//fmt.Printf("OpenAcc: endPoint %d is %s\n",
					//	i, n.endPoints[i].String())
					// END
				}
				if err == nil {
					n.acceptors = append(n.acceptors, acc) // XXX ACCEPTORS
				}
			}
		}
	}
	return
}

/**
 * This is not a graceful shutdown.
 */
func (n *Node) CloseAcc() (err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.running {
		// XXX STUB
		n.running = false

		// XXX should run down list of connections and close each,
		// XXX STUB

		// then run down list of acceptors and close any that are active
		if n.acceptors != nil {
			for i := 0; i < len(n.acceptors) && err == nil; i++ {
				if n.acceptors[i] != nil {
					err = n.acceptors[i].Close()
				}
			}
		}
	}
	return
}

// DIG_SIGNER ///////////////////////////////////////////////////////

// Returns an instance of a DigSigner which can be run in a separate
// goroutine.  This allows the Node to calculate more than one
// digital signature at the same time.
//
// XXX would prefer that *DigSigner be returned
func (n *Node) getSigner() *signer {
	return newSigner(n.skPriv)
}

// Returns a pointer to the node's RSA private comms key
func (n *Node) GetCommsPrivateKey() *rsa.PrivateKey {
	return n.ckPriv
}

// Returns a pointer to the node's RSA private sig key
func (n *Node) GetSigPrivateKey() *rsa.PrivateKey {
	return n.skPriv
}

// OVERLAYS /////////////////////////////////////////////////////////
//func (n *Node) AddOverlay(o xo.OverlayI) (ndx int, err error) {
//	ndx = -1
//	if o == nil {
//		err = NilOverlay
//	} else {
//		for i := 0; i < len(n.overlays); i++ {
//			if n.overlays[i].Equal(o) {
//				ndx = i
//				break
//			}
//		}
//		if ndx == -1 {
//			n.overlays = append(n.overlays, o)
//			ndx = len(n.overlays) - 1
//		}
//	}
//	return
//}
//
//func (n *Node) SizeOverlays() int {
//	return len(n.overlays)
//}
//
/////** @return how to access the peer (transport, protocol, address) */
//func (n *Node) GetOverlay(x int) xo.OverlayI {
//	return n.overlays[x]
//}

// PEERS ////////////////////////////////////////////////////////////

// Add a peer to the node's list of peers.  Return either the index of
// the peer in the resultant peer list or an error.
func (n *Node) AddPeer(peer *Peer) (ndx int, err error) {
	ndx = -1
	if peer == nil {
		err = NilPeer
	} else {
		if n.peers != nil {
			peerID := peer.GetNodeID().Value()
			for i := 0; i < len(n.peers); i++ {
				otherID := n.peers[i].GetNodeID().Value()
				if bytes.Equal(peerID, otherID) {
					ndx = i
					break
				}
			}
		}
		if ndx == -1 {
			// The peer was NOT already present.  Add it to the map.
			err = n.peerMap.Insert(peer.GetNodeID().Value(), peer)
			if err == nil {
				// add the peer to the list
				n.peers = append(n.peers, peer)
				ndx = len(n.peers) - 1
			}
		}
	}
	return
}

// Return a count,  the number of peers
func (n *Node) SizePeers() int {
	return len(n.peers)
}
func (n *Node) GetPeer(x int) *Peer {
	// XXX should return copy
	return n.peers[x]
}

// Return a pointer to the peer whose NodeID matches ID, or nil if
// there is no such peer.
func (n *Node) FindPeer(id []byte) (peer *Peer, err error) {
	if id == nil {
		err = NilID
	} else {
		var p interface{}
		p, err = n.peerMap.Find(id)
		if err == nil && p != nil {
			peer = p.(*Peer)
		}
	}
	return
}

// CONNECTIONS //////////////////////////////////////////////////////

func (n *Node) addConnection(c xt.ConnectionI) (ndx int, err error) {
	if c == nil {
		return -1, NilConnection
	}
	n.connections = append(n.connections, c)
	ndx = len(n.connections) - 1
	return
}

// Return a count of known Connections for this Peer.
func (n *Node) SizeConnections() int {
	return len(n.connections)
}

// Return a ConnectionI, an Address-Protocol pair identifying
// an Acceptor for the Peer.  Connections are arranged in order
// of preference, with the zero-th ConnectionI being the most
// preferred.  THESE ARE OPEN, LIVE CONNECTIONS.
//
// Returns the Nth Connection
func (n *Node) GetConnection(x int) xt.ConnectionI {
	return n.connections[x]
}

// LOCAL FILE SYSTEM ////////////////////////////////////////////////

// Return the path to the Node's local file system, its private
// persistent storage.  Conventionally there is a .xlattice subdirectory
// for storage of the Node's configuration information.
func (n *Node) GetLFS() string {
	return n.lfs
}

// Sets the path to the node's local storage.  If the directory does
// not exist, it creates it.

// XXX Note possible race condition!  What is the justification for
// this function??

func (n *Node) setLFS(val string) (err error) {

	if val == "" {
		err = NilLFS
	} else {
		err = xf.CheckLFS(val, 0700)
	}
	if err == nil {
		n.lfs = val
	}
	return
}

// EQUAL ////////////////////////////////////////////////////////////

func (n *Node) Equal(any interface{}) bool {
	if any == n {
		return true
	}
	if any == nil {
		return false
	}
	switch v := any.(type) {
	case *Node:
		_ = v
	default:
		return false
	}
	other := any.(*Node) // type assertion
	// THINK ABOUT publicKey.equals(any.publicKey)
	if n.nodeID == other.nodeID {
		return true
	}
	if n.nodeID.Length() != other.nodeID.Length() {
		return false
	}
	myVal := n.nodeID.Value()
	otherVal := other.nodeID.Value()
	for i := 0; i < n.nodeID.Length(); i++ {
		if myVal[i] != otherVal[i] {
			return false
		}
	}
	return false
}

// SERIALIZATION ////////////////////////////////////////////////////

func (n *Node) Strings() []string {
	ss := []string{"node {"}
	bns := n.BaseNode.Strings()
	for i := 0; i < len(bns); i++ {
		ss = append(ss, "    "+bns[i])
	}
	addStringlet(&ss, fmt.Sprintf("    lfs: %s", n.lfs))

	cPriv, _ := xc.RSAPrivateKeyToPEM(n.ckPriv)
	addStringlet(&ss, "    ckPriv: "+string(cPriv))

	sPriv, _ := xc.RSAPrivateKeyToPEM(n.skPriv)
	addStringlet(&ss, "    skPriv: "+string(sPriv))

	addStringlet(&ss, "    endPoints {")
	for i := 0; i < len(n.endPoints); i++ {
		addStringlet(&ss, "        "+n.GetEndPoint(i).String())
	}
	addStringlet(&ss, "    }")

	// peers
	addStringlet(&ss, "    peers {")
	for i := 0; i < len(n.peers); i++ {
		p := n.GetPeer(i).Strings()
		for j := 0; j < len(p); j++ {
			addStringlet(&ss, "        "+p[j])
		}
	}
	addStringlet(&ss, "    }")

	// gateways ?

	addStringlet(&ss, "}")
	return ss
}
func (n *Node) String() string {
	return strings.Join(n.Strings(), "\n")
}

// Collect an RSA private key in string form.  Only call this if
// '-----BEGIN -----' has already been seen

func ExpectRSAPrivateKey(rest *[]string) (key *rsa.PrivateKey, err error) {
	ss := []string{"-----BEGIN -----"}
	for {
		// NOT ROBUST; should detect end of rest, blank line, any other errors
		line := (*rest)[0]
		*rest = (*rest)[1:]
		ss = append(ss, line)
		if line == "-----END -----" {
			break
		}
	}
	if err == nil {
		text := strings.Join(ss, "\n")
		key, err = xc.RSAPrivateKeyFromPEM([]byte(text))
	}
	return
}
func Parse(s string) (node *Node, rest []string, err error) {
	ss := strings.Split(s, "\n")
	return ParseFromStrings(ss)
}
func ParseFromStrings(ss []string) (node *Node, rest []string, err error) {

	var line string
	var m *xi.IDMap
	bn, rest, err := ParseBNFromStrings(ss, "node")
	if err == nil {
		node = &Node{BaseNode: *bn}
		m, err = xi.NewNewIDMap()
		if err == nil {
			node.peerMap = m
		}
	}
	if err == nil {
		line, err = NextNBLine(&rest)
	}
	if err == nil {
		parts := strings.Split(line, ": ")
		if parts[0] == "lfs" {
			node.lfs = strings.TrimSpace(parts[1])
		} else {
			fmt.Println("MISSING LFS")
			err = NotASerializedNode
		}

		var ckPriv, skPriv *rsa.PrivateKey
		if err == nil {
			// move some of this into ExpectRSAPrivateKey() !
			line, err = NextNBLine(&rest)
			if err == nil {
				parts = strings.Split(line, ": ")
				if parts[0] == "ckPriv" && parts[1] == "-----BEGIN -----" {
					ckPriv, err = ExpectRSAPrivateKey(&rest)
					node.ckPriv = ckPriv
				} else {
					fmt.Println("MISSING OR ILL-FORMED COMMS_KEY")
					err = NotASerializedNode
				}
			}
		} // FOO

		if err == nil {
			// move some of this into ExpectRSAPrivateKey() !
			line, err = NextNBLine(&rest)
			if err == nil {
				parts = strings.Split(line, ": ")
				if parts[0] == "skPriv" && parts[1] == "-----BEGIN -----" {
					skPriv, err = ExpectRSAPrivateKey(&rest)
					node.skPriv = skPriv
				} else {
					fmt.Println("MISSING OR ILL-FORMED SIG_KEY")
					err = NotASerializedNode
				}
			}
		} // FOO

		// endPoints
		if err == nil {
			line, err = NextNBLine(&rest)
		}
		if err == nil {
			if line == "endPoints {" {
				for err == nil {
					line, err = NextNBLine(&rest)
					if err != nil {
						break
					}
					if line == "}" {
						// prepend := []string{line}
						// rest = append(prepend, rest...)
						break
					}
					var ep xt.EndPointI
					ep, err = xt.ParseEndPoint(line)
					if err != nil {
						break
					}
					_, err = node.AddEndPoint(ep)
					if err != nil {
						break
					}
				}
			} else {
				fmt.Println("MISSING END_POINTS BLOCK")
				fmt.Printf("    EXPECTED 'endPoints {', GOT: '%s'\n", line)
				err = NotASerializedNode
			}
		}

		// peers
		if err == nil {
			line, err = NextNBLine(&rest)
		}
		if err == nil {
			if line == "peers {" {
				for {
					line = strings.TrimSpace(rest[0])
					if line == "}" { // ZZZ
						break
					}
					var peer *Peer
					peer, rest, err = ParsePeerFromStrings(rest)
					if err != nil {
						break
					}
					_, err = node.AddPeer(peer)
					if err != nil {
						break
					}
				}
			} else {
				fmt.Println("MISSING PEERS BLOCK")
				fmt.Printf("    EXPECTED 'peers {', GOT: '%s'\n", line)
				err = NotASerializedNode
			}
			line, err = NextNBLine(&rest) // discard the ZZZ }

		}
		// gateways, but not yet
		// XXX STUB XXX

		// expect closing brace for node {
		// XXX we need an expect(&rest)

		line, err = NextNBLine(&rest)
		if err == nil {
			if line != "}" {
				fmt.Printf("extra text at end of node declaration: '%s'\n", line)
			}
		}
	}
	if err != nil {
		node = nil
	}
	return
}

// DIG SIGNER ///////////////////////////////////////////////////////

func (n *Node) Sign(chunks [][]byte) (sig []byte, err error) {
	if chunks == nil {
		err = NothingToSign
	} else {
		s := newSigner(n.skPriv)
		for i := 0; i < len(chunks); i++ {
			s.digest.Write(chunks[i])
		}
		h := s.digest.Sum(nil)
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, h)
	}
	return
}

type signer struct {
	key    *rsa.PrivateKey
	digest hash.Hash
}

func newSigner(key *rsa.PrivateKey) *signer {
	// XXX some validation, please
	h := sha1.New()
	ds := signer{key: key, digest: h}
	return &ds
}

///////////////////////////////////////////////////
// XXX This stuff needs to be cleaned up or dropped
///////////////////////////////////////////////////

func (s *signer) Algorithm() string {
	return "SHA1+RSA" // XXX NOT THE PROPER NAME
}
func (s *signer) Length() int {
	return 42 // XXX NOT THE PROPER VALUE
}
func (s *signer) Update(chunk []byte) {
	s.digest.Write(chunk)
}

// XXX 2013-07-15 Golang crypto package currently does NOT support SHA3 (Keccak)
func (s *signer) Sign() ([]byte, error) {
	h := s.digest.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, h)
	return sig, err
}

func (s *signer) String() string {
	return "NOT IMPLEMENTED"
}
