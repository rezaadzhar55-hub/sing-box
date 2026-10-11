package injector

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.InjectorOutboundOptions](registry, "injector", NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger   log.ContextLogger
	dialer   N.Dialer
	serverOpts option.ServerOptions
	payload  string
	waitResp bool
	respSize int
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.InjectorOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:  outbound.NewAdapterWithDialerOptions("injector", tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:   logger,
		dialer:   outboundDialer,
		serverOpts: options.ServerOptions,
		payload:  options.Payload,
		waitResp: options.WaitForResponse,
		respSize: options.ResponseSize,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "injector connection to ", destination)

	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverOpts.Build())
	if err != nil {
		return nil, err
	}

	payload := strings.ReplaceAll(h.payload, "[dest_host]", destination.AddrString())
	payload = strings.ReplaceAll(payload, "[dest_port]", fmt.Sprintf("%d", destination.Port))
	payload = strings.ReplaceAll(payload, "\r\n", "\r\n")
	payload = strings.ReplaceAll(payload, "\n", "\r\n")
	if !strings.HasSuffix(payload, "\r\n\r\n") {
		payload += "\r\n\r\n"
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err = conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return nil, err
	}
	if h.waitResp {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			conn.Close()
			return nil, err
		}
		h.logger.InfoContext(ctx, "injector response: ", string(buf[:min(n, 200)]))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func min(a, b int) int { if a < b { return a }; return b }
