package netcode

import (
	"bytes"
	"testing"

	"inet.af/netaddr"
)

func TestReadWriteShared(t *testing.T) {
	addrs := []string{"::1", "2001:db8::68", "127.0.0.1", "10.20.30.40"}

	for _, addr := range addrs {
		readWriteShared(t, addr)
	}
}

func readWriteShared(t *testing.T, addr string) {
	var err error
	var clientKey []byte
	var serverKey []byte
	clientKey, err = RandomBytes(KEY_BYTES)
	if err != nil {
		t.Fatalf("error generating client key")
	}

	serverKey, err = RandomBytes(KEY_BYTES)
	if err != nil {
		t.Fatalf("error generating server key")
	}

	ip, err := netaddr.ParseIP(addr)
	if err != nil {
		t.Fatalf(("error parsing ip"))
	}

	server := netaddr.IPPort{IP: ip, Port: 40000}
	data := &sharedTokenData{}
	data.TimeoutSeconds = 10
	data.ServerAddrs = make([]netaddr.IPPort, 1)
	data.ServerAddrs[0] = server
	data.ClientKey = clientKey
	data.ServerKey = serverKey

	buffer := NewBuffer(CONNECT_TOKEN_BYTES)
	if err := data.WriteShared(buffer); err != nil {
		t.Fatalf("error writing shared buffer: %s\n", err)
	}

	// reset
	buffer.Reset()
	outData := &sharedTokenData{}

	if err := outData.ReadShared(buffer); err != nil {
		t.Fatalf("error reading data: %s\n", err)
	}

	if !bytes.Equal(clientKey, outData.ClientKey) {
		t.Fatalf("timeout seconds did not match\nexpected: %d\ngot: %d\n", data.TimeoutSeconds, outData.TimeoutSeconds)
	}

	if !bytes.Equal(clientKey, outData.ClientKey) {
		t.Fatalf("client key did not match\nexpected: %#v\ngot: %#v\n", clientKey, outData.ClientKey)
	}

	if !bytes.Equal(serverKey, outData.ServerKey) {
		t.Fatalf("server key did not match")
	}

	if outData.ServerAddrs[0].IP != server.IP {
		t.Fatalf("server address did not match\nexpected: %s\ngot: %s\n", server.IP, outData.ServerAddrs[0].IP)
	}
}
