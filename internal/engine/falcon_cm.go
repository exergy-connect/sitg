package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Falcon assigns connection establishment to the software control plane. This
// versioned TCP protocol is SITG's lab CM, not an OCP Falcon packet type.
const falconCMVersion = "sitg-falcon-cm/1"
const maxFalconConnections = 1024

type falconHello struct {
	Protocol string
	CID      uint32 // receive CID allocated by the sender of this message
	Service  uint32 // receiver's --qp, used to select the listening service
	Encap    string
	Payload  int
	Window   int
	Error    string `json:",omitempty"`
}

func (h falconHello) validate() error {
	if h.Protocol != falconCMVersion || h.CID > 0xffffff || h.Payload < 1 || h.Payload > 9000 || h.Window < 1 || h.Window > 64 || (h.Encap != "udp4" && h.Encap != "udp6") || h.Error != "" {
		return fmt.Errorf("invalid or incompatible Falcon CM parameters: %+v", h)
	}
	return nil
}

func (e *Engine) falconHello(cid uint32) falconHello {
	return falconHello{Protocol: falconCMVersion, CID: cid, Service: e.cfg.QP, Encap: string(e.cfg.Encap), Payload: e.cfg.PktSize, Window: min(e.cfg.Window, 64)}
}

// CIDs are never reused within a process, including after failed setup/close.
// A fresh receiver instance must not overlap an older instance's traffic.
type falconCIDAllocator struct{ next uint32 }

func (a *falconCIDAllocator) allocate() (uint32, error) {
	if a.next > 0xffffff {
		return 0, fmt.Errorf("Falcon receive CID space exhausted")
	}
	cid := a.next
	a.next++
	return cid, nil
}

type falconCMEvent struct {
	conn  net.Conn
	peer  netip.Addr
	local netip.Addr
	hello falconHello
	reply chan falconHello // nil means connection closed
}

func falconPeer(conn net.Conn) netip.Addr {
	return conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
}

// The server serializes installation/removal through the receive engine. State
// is installed before a success reply can reach the sender, so data cannot race
// setup. TCP EOF is the teardown signal; setup has a bounded read/write deadline.
func serveFalconCM(ctx context.Context, listener net.Listener, timeout time.Duration, events chan<- falconCMEvent) {
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, maxFalconConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots; _ = conn.Close() }()
			stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopConn()
			_ = conn.SetDeadline(time.Now().Add(timeout))
			var hello falconHello
			if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&hello); err != nil {
				return
			}
			reply := make(chan falconHello, 1)
			event := falconCMEvent{conn: conn, peer: falconPeer(conn), local: conn.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap(), hello: hello, reply: reply}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
			defer func() {
				select {
				case events <- falconCMEvent{conn: conn}:
				case <-ctx.Done():
				}
			}()
			var response falconHello
			select {
			case response = <-reply:
			case <-ctx.Done():
				return
			}
			if err := json.NewEncoder(conn).Encode(response); err != nil || response.Error != "" {
				return
			}
			_ = conn.SetDeadline(time.Time{})
			// No further application messages are defined. EOF or unexpected bytes close
			// the association, rather than retaining a dead connection indefinitely.
			var b [1]byte
			_, _ = conn.Read(b[:])
		}()
	}
}

func (e *Engine) dialFalcon(ctx context.Context, peer netip.Addr, localCID uint32) (*falconConnection, error) {
	src, err := e.srcIP()
	if err != nil {
		return nil, err
	}
	setupCtx, cancel := context.WithTimeout(ctx, e.cfg.ConnectTimeout)
	defer cancel()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(src.AsSlice())}}
	conn, err := d.DialContext(setupCtx, "tcp", net.JoinHostPort(peer.String(), strconv.Itoa(e.cfg.FalconCMPort)))
	if err != nil {
		return nil, fmt.Errorf("Falcon setup with %s: %w", peer, err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(setupCtx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := setupCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	hello := e.falconHello(localCID)
	if err := hello.validate(); err != nil {
		return nil, err
	}
	if err := json.NewEncoder(conn).Encode(hello); err != nil {
		return nil, err
	}
	var response falconHello
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&response); err != nil {
		return nil, fmt.Errorf("Falcon setup reply from %s: %w", peer, err)
	}
	if response.Error != "" {
		return nil, fmt.Errorf("Falcon setup rejected by %s: %s", peer, response.Error)
	}
	if err := response.validate(); err != nil {
		return nil, err
	}
	if response.Service != hello.Service || response.Encap != hello.Encap || response.Payload > hello.Payload || response.Window > hello.Window {
		return nil, fmt.Errorf("Falcon peer returned incompatible negotiation")
	}
	if err := setupCtx.Err(); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	c := &falconConnection{peer: peer, localCID: localCID, remoteCID: response.CID, payload: response.Payload, window: NewSendWindow(response.Window, e.cfg.RTO), cm: conn, closed: make(chan struct{})}
	go func() { var b [1]byte; _, _ = conn.Read(b[:]); close(c.closed) }()
	success = true
	return c, nil
}
