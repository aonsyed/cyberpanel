//go:build !linux

package apiserver

import "net"

func(policy *StaticPeerPolicy)Authorize(net.Conn)error{return ErrUntrustedPeer}
