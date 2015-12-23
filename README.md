# xlNode_go

The **Node** component library for
[xlattice.](https://jddixon.github.io/xlattice_go)

A Node is the basic building block for an XLattice network.

An XLattice node is an independent thread or process which has

1. a **name**, a convenience for testing; it need not be unique (although
   it is better if it is)
2. a **nodeID**, a 20- or 32-byte value, which should be globally unique
3. an RSA key for use in encrypting small messages, its **commsKey**
4. a second RSA key used for signing documents, its **sigKey**
5. a number of **Overlays** though which it communicates

These fields constitute the **BaseNode**.  The node also has

* a local file system, its **LFS**, for persistent storage
* a number of **endPoints**; in the current implementation each of these
  consists of an IP address and port number that the node listens on
* a set of **Peers**, other nodes with which it may exchange traffic and
* a **PeerMap** which maps nodeIDs to the corresponding Peer
* optionally a set of **Gateways**, which route traffic to Nodes on
  otherwise inaccessiable Overlays

## NodeID

A [NodeID](https://jddixon.github.io/xlNodeID_go)
is a 160- or 256-bit value, typically generated by SHA-1 or SHA-256,
where SHA is the Secure Hash Algorithm.  It is not unreasonable
to hash one or both of the node's **public** RSA keys to generate its nodeID.

## CommsKey (ck)

The RSA algorithm limits messages to something less than the key size,
so a few hundred bytes.  RSA is also compute-intensive and so quite slow.
Given these considerations, RSA is normally used only to set up a session
and then a much faster block cipher such as AES is used to encrypt the rest
of the session traffic.  If the session is long-lived, the session key
might be renegotiated every hour or so.

In this approach, one XLattice node (acting as the server) will publish
its RSA public key.  Another XLattice (actign as a client) will use this
public key to encrypt a message which can only be decrypted by the server,
using its RSA private key.  In a short exchange, the two will agree on a
block cipher session key.  All further messages are encrypted using that
session key.

## SigKey (sk)

It is widely believed that it is less safe to use the same keys for both
encryption and digital signatures.  So the XLattice node has two RSA keys,
the commsKey described above and then a second key, the sigKey, used for
generating digital signatures.

Standard practice is to make an XLattice node's nodeID and the public
parts of the commsKey and sigKey available to all prospective Peers,
so that the comms public key can be used to encrypt the secret message(s)
used to initiate sessions and the sig public key can be used to verify
digital signatures supposedly created using the server's sig private key.

## Local File System

A node's local file system is persistent store associated with the
node.  The node may stores its configuration data there, so that the
node can recover from failures.  Standard practice is to store
application-specific data in the LFS and basic configuraton data in
LFS/.xlattice/node.config

## EndPoints

In this context an endPoint is an address/port combination which the
node listens on.  There must be at least one such endPoint, or the
node will be unreachable.  In the current implementation an endPoint
is serialized like so:

    TcpEndPoint: 127.0.0.1:60319

This endPoint uses Tcp.  It listens on `127.0.0.1`, the Linux/POSIX
**localhost**, at port `60319`.

## Peers

A **peer** is another XLattice node, or something which behaves like
one.  When an XLattic3 node is started, it might be provided with a
list of Peers, possibly from the configuration file in its LFS.
Alternatively, it might learn a peer's **baseNode** details when
the peer connects to one of the node's endPoints.  In any case,
the node maintains a table of peer descriptors, including the public
part of each peer's RSA keys.

## PeerMap

Given a nodeID, a PeerMap returns a pointer to a descriptor for the
peer, should the peer be known to the XLattice node.

## Gateway

A **Gateway** is not the same as a router, although it may be resident on
a router.  A Node communicating with an otherwise unreachable Node routes
messages through an Internet Protocol (IP) network to the Gateway, which
forwards the messages though an address on the remote Overlay to the
destination Node.  The remote Node will route traffic back in the same
manner, usually but not necessarily using the same Gateway.

## Project Status

Both specifications and code are stable, although Gateways have not been
implemented.  All tests succeed.

## On-line Documentation

More information on the **xlNode_go** project can be found
[here](https://jddixon.github.io/xlNode_go)
