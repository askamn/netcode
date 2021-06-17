package netcode

import "inet.af/netaddr"

type NetcodeAddress struct {
	Hostname string
	Port     uint16
	IPPort   netaddr.IPPort
}
