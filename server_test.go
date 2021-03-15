package netcode

import (
	"testing"
	"time"

	"inet.af/netaddr"
)

type SendFunc func(serv *Server, payload []byte)

func TestServerListen(t *testing.T) {
	port := 40000
	doneCh := make(chan struct{})
	go runTestServer(port, testSendFunc, doneCh, t)
	go runTestClient(port, t)
	<-doneCh
}

func TestServerSendPayloadToClient(t *testing.T) {
	port := 40001
	doneCh := make(chan struct{})
	go runTestServer(port, testSendToClientFunc, doneCh, t)
	go runTestClient(port, t)
	<-doneCh
}

// Tests sending payloads to all connected clients
func testSendFunc(serv *Server, payload []byte) {
	// send payloads to clients
	serv.SendPayloads(payload)
}

// Tests sending to individual clients via their ClientIds
func testSendToClientFunc(serv *Server, payload []byte) {
	// do simulation/process payload packets
	clientIds := serv.GetConnectedClientIds()
	if len(clientIds) > 0 {
		for _, clientId := range clientIds {
			serv.SendPayloadToClient(clientId, payload)
		}
	}
}

func runTestServer(port int, sendFunc SendFunc, doneCh chan struct{}, t *testing.T) {
	maxClients := 32
	ip, _ := netaddr.ParseIP("127.0.0.1")
	addr := netaddr.IPPort{IP: ip, Port: uint16(port)}
	serv := NewServer(&addr, TEST_PRIVATE_KEY, TEST_PROTOCOL_ID, maxClients)
	if err := serv.Init(); err != nil {
		t.Fatalf("error initializing server: %s\n", err)
	}
	defer serv.Stop()

	if err := serv.Listen(); err != nil {
		t.Fatalf("error listening: %s\n", err)
	}

	payload := make([]byte, MAX_PAYLOAD_BYTES)
	for i := 0; i < len(payload); i += 1 {
		payload[i] = byte(i)
	}
	serverTime := float64(0.0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta * float64(time.Second))
	count := 0
	payloadCount := 0
	for {
		serv.Update(serverTime)
		if count > 0 && payloadCount > 0 {
			close(doneCh)
			return
		}

		for i := 0; i < serv.MaxClients(); i += 1 {
			for {
				responsePayload, _ := serv.RecvPayload(i)
				if len(responsePayload) == 0 {
					break
				}
				payloadCount++
				t.Logf("got payload: %d\n", len(responsePayload))
			}
		}

		// do simulation/process payload packets

		// send payloads to clients
		//sendFunc(serv, payload, serverTime)
		serv.SendPayloads(payload)

		time.Sleep(deltaTime)
		serverTime += deltaTime.Seconds()
		count += 1
	}
}

func runTestClient(port int, t *testing.T) {
	ip, _ := netaddr.ParseIP("127.0.0.1")
	server := netaddr.IPPort{IP: ip, Port: uint16(port)}
	servers := make([]netaddr.IPPort, 1)
	servers[0] = server

	connectToken := testGenerateConnectToken(servers, TEST_PRIVATE_KEY, t)

	clientTime := float64(0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta * float64(time.Second))

	c := NewClient(connectToken)

	if err := c.Connect(); err != nil {
		t.Fatalf("error connecting: %s\n", err)
	}
	defer c.Close()

	packetData := make([]byte, MAX_PAYLOAD_BYTES)
	for i := 0; i < MAX_PAYLOAD_BYTES; i += 1 {
		packetData[i] = byte(i)
	}
	count := 0

	// fake game loop
	for {
		if count == 20 {

			t.Fatalf("never recv'd a payload packet after 20 iterations")
			return
		}

		c.Update(clientTime)
		if c.GetState() == StateConnected {
			c.SendData(packetData)
		}

		for {
			if payload, seq := c.RecvData(); payload == nil {
				break
			} else {
				t.Logf("seq: %d recv'd payload: of %d bytes\n", seq, len(payload))
				return
			}
		}
		time.Sleep(deltaTime)
		clientTime += deltaTime.Seconds()
		count++
	}
}
