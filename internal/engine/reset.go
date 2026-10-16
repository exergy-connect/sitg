package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/jbemmel/sitg/internal/config"
)

// Reset only this sender's endpoint/QP, and wait until the receive loop has
// removed the old tracker before allowing a new sequence space to start.
func (e *Engine) resetReceivers(ctx context.Context) error {
	protocols := []string{string(e.cfg.Proto)}
	if e.cfg.Proto == config.ProtoFalcon {
		return nil
	}
	if e.cfg.Proto == config.ProtoMixed {
		protocols = []string{"uet", "mrc"}
	}
	src, err := e.srcIP()
	if err != nil {
		return err
	}
	for _, peer := range e.sel.Peers() {
		for _, proto := range protocols {
			err := func() error {
				setupCtx, cancel := context.WithTimeout(ctx, e.cfg.ConnectTimeout)
				defer cancel()
				d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(src.AsSlice())}}
				conn, err := d.DialContext(setupCtx, "tcp", net.JoinHostPort(peer.String(), strconv.Itoa(e.cfg.FalconCMPort)))
				if err != nil {
					return err
				}
				defer conn.Close()
				stop := context.AfterFunc(setupCtx, func() { _ = conn.Close() })
				defer stop()
				deadline, _ := setupCtx.Deadline()
				_ = conn.SetDeadline(deadline)
				request := falconHello{Protocol: "sitg-flow-reset/1", ResetProto: proto, Service: e.cfg.QP, Encap: string(e.cfg.Encap)}
				if err := json.NewEncoder(conn).Encode(request); err != nil {
					return err
				}
				var reply falconHello
				if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&reply); err != nil {
					return err
				}
				if reply.Error != "" {
					return fmt.Errorf("%s", reply.Error)
				}
				if reply.Protocol != request.Protocol || reply.ResetProto != proto || reply.Service != request.Service || reply.Encap != request.Encap {
					return fmt.Errorf("invalid reset reply")
				}
				return nil
			}()
			if err != nil {
				return fmt.Errorf("reset %s receiver %s: %w", proto, peer, err)
			}
		}
	}
	return nil
}
