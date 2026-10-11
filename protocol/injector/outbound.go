package injector

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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
	logger    log.ContextLogger
	dialer    N.Dialer
	serverOps option.ServerOptions
	payload   string
	wsMode    bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.InjectorOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions("injector", tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:    logger,
		dialer:    outboundDialer,
		serverOps: options.ServerOptions,
		payload:   options.Payload,
		wsMode:    options.WebsocketMode,
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

	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverOps.Build())
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = conn.Write([]byte(h.payload)); err != nil {
		conn.Close()
		return nil, err
	}
	if h.wsMode {
		// tunggu 101 header
		buf := make([]byte, 0, 1024)
		tmp := make([]byte, 512)
		for !strings.Contains(string(buf), "\r\n\r\n") {
			n, err := conn.Read(tmp)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("injector: ws handshake read: %w", err)
			}
			buf = append(buf, tmp[:n]...)
			if len(buf) > 8192 {
				break
			}
		}
		if !strings.Contains(string(buf), "101") && !strings.Contains(string(buf), " 200 ") {
			conn.Close()
			return nil, fmt.Errorf("injector: ws handshake gagal: %s", firstLine(buf))
		}
		if strings.Contains(string(buf), " 200 ") && !strings.Contains(string(buf), "101") {
			h.logger.InfoContext(ctx, "injector: 200 payload mode diterima")
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		}
		h.logger.InfoContext(ctx, "injector: ws 101 diterima")
		_ = conn.SetDeadline(time.Time{})
		return &wsRawConn{Conn: conn}, nil
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s[:min(len(s), 80)]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// wsRawConn membungkus raw TCP menjadi koneksi WS-client (masked frame out, unmask in)
type wsRawConn struct {
	net.Conn
	rbuf []byte
}

func (c *wsRawConn) Write(b []byte) (int, error) {
	// satu frame binary masked (payload <= 16MB)
	n := len(b)
	hdr := []byte{0x82}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	switch {
	case n < 126:
		hdr = append(hdr, byte(0x80|n))
	case n < 65536:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	hdr = append(hdr, mask...)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = b[i] ^ mask[i%4]
	}
	if _, err := c.Conn.Write(append(hdr, masked...)); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *wsRawConn) Read(b []byte) (int, error) {
	for len(c.rbuf) < 2 {
		tmp := make([]byte, 4096)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.rbuf = append(c.rbuf, tmp[:n]...)
	}
	b1 := c.rbuf[0]
	b2 := c.rbuf[1]
	opcode := b1 & 0x0F
	ln := int(b2 & 0x7F)
	off := 2
	switch ln {
	case 126:
		for len(c.rbuf) < off+2 {
			tmp := make([]byte, 4096)
			n, err := c.Conn.Read(tmp)
			if err != nil {
				return 0, err
			}
			c.rbuf = append(c.rbuf, tmp[:n]...)
		}
		ln = int(binary.BigEndian.Uint16(c.rbuf[off : off+2]))
		off += 2
	case 127:
		for len(c.rbuf) < off+8 {
			tmp := make([]byte, 4096)
			n, err := c.Conn.Read(tmp)
			if err != nil {
				return 0, err
			}
			c.rbuf = append(c.rbuf, tmp[:n]...)
		}
		ln = int(binary.BigEndian.Uint64(c.rbuf[off : off+8]))
		off += 8
	}
	for len(c.rbuf) < off+ln {
		tmp := make([]byte, 4096)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.rbuf = append(c.rbuf, tmp[:n]...)
	}
	payload := c.rbuf[off : off+ln]
	c.rbuf = c.rbuf[off+ln:]
	switch opcode {
	case 0x8: // close
		return 0, io.EOF
	case 0x9: // ping -> sudah; abaikan (server kami tidak ping saat passthrough)
		return c.Read(b)
	}
	// opcode 0x1/0x2/0x0: data
	n := copy(b, payload)
	return n, nil
}

func (c *wsRawConn) Close() error {
	// kirim close frame best-effort
	c.Conn.Write([]byte{0x88, 0x80, 0, 0, 0})
	return c.Conn.Close()
}
