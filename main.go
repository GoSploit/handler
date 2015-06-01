// GoPloitHandler project main.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosploit/protocol"
)

var (
	Sessions    = make(map[int64]*Session)
	SessionSync sync.Mutex
	SessionID   int64
)

type Request struct {
	Controller *Controller
	packet     *protocol.Packet
}

type Session struct {
	ID        int64
	Request   chan *Request
	requests  map[int64]*Request
	requestID int64
}

type Controller struct {
	Recv    *json.Decoder
	Send    *json.Encoder
	Session *Session
}

func main() {

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 365 * 24)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "GoPloit",
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PublicKey: priv.PublicKey,

		DNSNames: []string{"andyleap.net"},

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	certbytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)

	cert := tls.Certificate{
		Certificate: [][]byte{certbytes},
		PrivateKey:  priv,
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	listener, _ := tls.Listen("tcp", ":443", config)
	controlListener, _ := net.Listen("tcp", "127.0.0.1:8989")
	go ControllerListener(controlListener)

	fmt.Println("Ready")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			conn.Close()
			continue
		}
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			fmt.Println(err)
			conn.Close()
			continue
		}
		go Handler(conn)
	}
}

func Handler(c net.Conn) {
	recv := json.NewDecoder(c)
	send := json.NewEncoder(c)
	session := &Session{
		ID:       atomic.AddInt64(&SessionID, 1),
		Request:  make(chan *Request),
		requests: make(map[int64]*Request),
	}
	SessionSync.Lock()
	Sessions[session.ID] = session
	SessionSync.Unlock()
	fmt.Println("New Payload Session")
	done := make(chan bool)
	go func() {
		for {
			select {
			case req := <-session.Request:
				p := &protocol.Packet{}
				*p = *req.packet
				p.ID = session.requestID
				session.requestID = session.requestID + 1
				session.requests[p.ID] = req
				send.Encode(p)
			case <-done:
				return
			}
		}
	}()
	for {
		var p *protocol.Packet
		err := recv.Decode(&p)
		if err != nil {
			fmt.Println(err)
			done <- true
			return
		}
		req, ok := session.requests[p.ID]
		if ok {
			p.ID = req.packet.ID
			req.Controller.Send.Encode(p)
			delete(session.requests, p.ID)
		}
	}
}

func ControllerListener(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			conn.Close()
			continue
		}
		go ControlHandler(conn)
	}
}

func ControlHandler(c net.Conn) {
	recv := json.NewDecoder(c)
	send := json.NewEncoder(c)
	controller := &Controller{
		Recv: recv,
		Send: send,
	}
	for {
		var p *protocol.Packet
		err := recv.Decode(&p)
		if err != nil {
			return
		}
		switch msg := p.Msg.(type) {
		case protocol.GetSessionsRequest:
			SessionSync.Lock()
			sessionsInfo := make([]protocol.SessionInfo, 0)
			for id := range Sessions {
				sessionsInfo = append(sessionsInfo, protocol.SessionInfo{
					ID: id,
				})
			}
			SessionSync.Unlock()
			resp := &protocol.Packet{
				ID: p.ID,
				Msg: protocol.GetSessionsResponse{
					Sessions: sessionsInfo,
				},
			}
			send.Encode(resp)
		case protocol.SelectSessionRequest:
			SessionSync.Lock()
			sess, ok := Sessions[msg.ID]
			SessionSync.Unlock()
			resp := &protocol.Packet{
				ID:  p.ID,
				Msg: protocol.SelectSessionResponse{},
			}
			if ok {
				controller.Session = sess
			} else {
				resp.Msg = protocol.SelectSessionResponse{
					Error: "No such session",
				}
			}
			send.Encode(resp)
		default:
			if controller.Session != nil {
				controller.Session.Request <- &Request{
					packet:     p,
					Controller: controller,
				}
			}
		}
	}
}
