package netcode

import (
	"fmt"
	"net"

	"inet.af/netaddr"
)

// ip types used in serialization of server addresses
const (
	ADDRESS_NONE = iota
	ADDRESS_IPV4
	ADDRESS_IPV6
)

// This struct contains data that is shared in both public and private parts of the
// connect token.
type sharedTokenData struct {
	TimeoutSeconds int32            // timeout in seconds. -1 means disable timeout (dev only).
	ServerAddrs    []NetcodeAddress // list of server addresses this client may connect to
	ClientKey      []byte           // client to server key
	ServerKey      []byte           // server to client key
}

func (shared *sharedTokenData) GenerateShared() error {
	var err error

	if shared.ClientKey, err = GenerateKey(); err != nil {
		return fmt.Errorf("error generating client key: %s", err)
	}

	if shared.ServerKey, err = GenerateKey(); err != nil {
		return fmt.Errorf("error generating server key: %s", err)
	}
	return nil
}

// Reads and validates the servers, client <-> server keys.
func (shared *sharedTokenData) ReadShared(buffer *Buffer) error {
	var err error
	var servers uint32
	var ipBytes []byte

	shared.TimeoutSeconds, err = buffer.GetInt32()
	if err != nil {
		return err
	}

	servers, err = buffer.GetUint32()
	if err != nil {
		return err
	}

	if servers <= 0 {
		return ErrEmptyServers
	}

	if servers > MAX_SERVERS_PER_CONNECT {
		return ErrTooManyServers
	}

	shared.ServerAddrs = make([]NetcodeAddress, servers)

	for i := 0; i < int(servers); i += 1 {
		serverType, err := buffer.GetUint8()
		if err != nil {
			return err
		}

		if serverType == ADDRESS_IPV4 {
			ipBytes, err = buffer.GetBytes(4)
			if err != nil {
				return err
			}
		} else if serverType == ADDRESS_IPV6 {
			ipBytes = make([]byte, 16)
			for i := 0; i < 16; i += 2 {
				n, err := buffer.GetUint16()
				if err != nil {
					return err
				}
				// decode little endian -> big endian for net.IP
				ipBytes[i] = byte(n >> 8)
				ipBytes[i+1] = byte(n)
			}
		} else {
			return ErrUnknownIPAddress
		}

		ip, ok := netaddr.FromStdIPRaw(net.IP(ipBytes))
		if !ok {
			return ErrUnknownIPAddress
		}

		port, err := buffer.GetUint16()
		if err != nil {
			return ErrInvalidPort
		}

		shared.ServerAddrs[i] = NetcodeAddress{Hostname: "", Port: port, IPPort: netaddr.IPPort{IP: ip, Port: port}}
	}

	if shared.ClientKey, err = buffer.GetBytes(KEY_BYTES); err != nil {
		return err
	}

	if shared.ServerKey, err = buffer.GetBytes(KEY_BYTES); err != nil {
		return err
	}

	return nil
}

// Writes the servers and client <-> server keys to the supplied buffer
func (shared *sharedTokenData) WriteShared(buffer *Buffer) error {
	buffer.WriteInt32(shared.TimeoutSeconds)
	buffer.WriteUint32(uint32(len(shared.ServerAddrs)))

	for _, addr := range shared.ServerAddrs {
		addressLength := uint16(len(addr.Hostname))
		if addressLength == 0 {
			return ErrInvalidIPAddress
		}

		// Write the hostname
		buffer.WriteUint16(addressLength)
		buffer.WriteBytes([]byte(addr.Hostname))

		// Write the port
		buffer.WriteUint16(uint16(addr.Port))
	}

	buffer.WriteBytesN(shared.ClientKey, KEY_BYTES)
	buffer.WriteBytesN(shared.ServerKey, KEY_BYTES)
	return nil
}
