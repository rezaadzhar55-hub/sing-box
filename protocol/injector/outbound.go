package injector

import (
	"crypto/tls"
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
	proxy     string
	method    string
	useTls    bool
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
		proxy:     options.Proxy,
		method:    options.Method,
		useTls:    options.TLS,
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

	dialOps := h.serverOps
	if h.proxy != "" {
		// remote proxy (gaya HI): dial ke proxy; payload Host tetap = bug host asli
		h.logger.InfoContext(ctx, "Alamat Remote Proksi: ", h.proxy)
		sa := M.ParseSocksaddrHostPortStr(h.proxy, "80")
		dialOps = option.ServerOptions{Server: sa.AddrString(), ServerPort: sa.Port}
	}
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, dialOps.Build())
	if err != nil && h.proxy != "" {
		h.logger.InfoContext(ctx, "injector: dial proxy gagal, fallback langsung: ", err)
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverOps.Build())
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	// mode TLS: bungkus koneksi dgn TLS sebelum payload/SSH
	if h.useTls {
		serverName := h.serverOps.Server
		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("injector: tls handshake gagal: %w", err)
		}
		conn = tlsConn
		h.logger.InfoContext(ctx, "injector: tls handshake ok")
	}
	if h.method == "tls" || h.payload == "" {
		// tanpa payload: langsung SSH banner
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
	norm := strings.ReplaceAll(strings.ReplaceAll(h.payload, "\r\n", "\n"), "\n", "\r\n")
	// Cloudflare hanya meneruskan WS-upgrade jika ada Sec-WebSocket-Key. Payload HI sering
	// tanpa key (mis. "GET / ... Upgrade: websocket") -> CF membalas sendiri dan koneksi mati.
	// Solusi: sisipkan key otomatis bila ada "Upgrade: websocket" tanpa key.
	if strings.Contains(strings.ToLower(norm), "upgrade: websocket") &&
		!strings.Contains(strings.ToLower(norm), "sec-websocket-key:") {
		keyLine := "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		norm = strings.Replace(norm, "Upgrade: websocket\r\n",
			"Upgrade: websocket\r\n"+keyLine, 1)
		h.logger.InfoContext(ctx, "Sec-WebSocket-Key ditambahkan otomatis (kompat Cloudflare)")
	}
	h.logger.InfoContext(ctx, "Format Payload: ", strings.ReplaceAll(norm, "\r\n", " | "))
	h.logger.InfoContext(ctx, "Mengirim payload")
	if !strings.HasSuffix(norm, "\r\n\r\n") {
		norm += "\r\n" // header harus diakhiri blank line
		if !strings.HasSuffix(norm, "\r\n\r\n") {
			norm += "\r\n"
		}
	}
	// HI-parity: saat remote proxy dipakai, payload dikirim ke proxy dan server front
	// umumnya menuntut Host = host-nya sendiri (kalau tidak -> 400 Bad Request).
	// Ganti baris Host: dalam payload menjadi host remote proxy, tujuan asli
	// disisipkan di X-Host agar server injector HI-style tetap tahu bug host.
	if h.proxy != "" {
		proxyHost := h.proxy
		if i := strings.Index(proxyHost, ":"); i > 0 {
			proxyHost = proxyHost[:i]
		}
		oldHost := "Host: " + h.serverOps.Server
		if strings.Contains(norm, oldHost) {
			norm = strings.Replace(norm, oldHost,
				"Host: "+proxyHost+"\r\nX-Host: "+h.serverOps.Server, 1)
			h.logger.InfoContext(ctx, "Host diganti ke remote proxy (HI-style): ", proxyHost)
		}
	}
	if _, err = conn.Write([]byte(norm)); err != nil {
		conn.Close()
		return nil, err
	}
	if h.wsMode {
		// baca respons header HTTP pertama (berhenti tepat di akhir header).
		// sisa byte SETELAH header (mis. banner SSH dari server) DISIMPAN utk stream,
		// jangan dibuang — ini kunci kompatibilitas semua server injector.
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		headerEnd := -1
		for headerEnd < 0 {
			n, err := conn.Read(tmp)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("injector: ws handshake read: %w", err)
			}
			buf = append(buf, tmp[:n]...)
			headerEnd = strings.Index(string(buf), "\r\n\r\n")
			if len(buf) > 65536 {
				break
			}
		}
		first := firstLine(buf)
		h.logger.InfoContext(ctx, first) // log HI-style: HTTP/1.1 101/200...
		_ = conn.SetDeadline(time.Time{})
		if headerEnd < 0 {
			// header tidak lengkap: anggap raw, langsung serahkan
			return conn, nil
		}
		if strings.Contains(first, "101") || strings.Contains(first, " 200 ") {
			// handshake ok. sisanya setelah header = data dari server (banner SSH),
			// kembalikan lewat wrapper agar tidak hilang
			rest := buf[headerEnd+4:]
			if len(rest) > 0 {
				return &prefixedConn{Conn: conn, prefix: rest}, nil
			}
			return conn, nil
		}
		// respons selain 101/200: tetap lanjut (server injector lain mungkin
		// balas 302/400 tapi tunnel tetap raw) — gaya HI yang pemaaf
		h.logger.InfoContext(ctx, "injector: respons non-101/200, lanjut raw: ", first)
		rest := buf[headerEnd+4:]
		if len(rest) > 0 {
			return &prefixedConn{Conn: conn, prefix: rest}, nil
		}
		return conn, nil
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// prefixedConn: stream dgn byte tersisa dari respons HTTP sebelum data SSH
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
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
