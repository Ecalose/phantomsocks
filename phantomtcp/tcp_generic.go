//go:build !linux && !windows

package phantomtcp

import (
	"net"
	"time"
)

func DialWithOption(laddr, raddr *net.TCPAddr, ttl, mss int, tcpfastopen, keepalive bool, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
	return d.Dial("tcp", raddr.String())
}

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())
	if err != nil {
		return nil, err
	}

	return LocalTCPAddr, err
}

func SendWithOption(conn net.Conn, payload, oob []byte, tos, ttl int) error {
	return nil
}

func (outbound *Outbound)SendWithFakePayload(conn net.Conn, fakepayload, realpayload []byte) error {
	return nil
}

func GetTCPState(conn net.Conn) (uint8, error) {
	return 0, nil
}

func TProxyTCP(address string) {
}
