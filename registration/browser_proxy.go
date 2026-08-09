package registration

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type authenticatedProxyBridge struct {
	server   *http.Server
	listener net.Listener
	upstream string
	auth     string
}

func startAuthenticatedProxyBridge(ctx context.Context, proxy *browserProxy) (string, func(), error) {
	if proxy == nil || proxy.username == "" {
		return "", nil, fmt.Errorf("authenticated proxy configuration is missing")
	}
	if len(proxy.server) < len("http://") || proxy.server[:len("http://")] != "http://" {
		return "", nil, fmt.Errorf("authenticated browser proxy currently requires an HTTP proxy endpoint")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("start local browser proxy bridge: %w", err)
	}
	bridge := &authenticatedProxyBridge{
		listener: listener,
		upstream: proxy.server[len("http://"):],
		auth:     "Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.username+":"+proxy.password)),
	}
	bridge.server = &http.Server{
		Handler:           bridge,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	go func() {
		_ = bridge.server.Serve(listener)
	}()
	closeBridge := func() {
		_ = bridge.server.Close()
		_ = bridge.listener.Close()
	}
	go func() {
		<-ctx.Done()
		closeBridge()
	}()
	return "http://" + listener.Addr().String(), closeBridge, nil
}

func (b *authenticatedProxyBridge) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect {
		b.forwardHTTP(writer, request)
		return
	}
	upstream, err := net.DialTimeout("tcp", b.upstream, 15*time.Second)
	if err != nil {
		http.Error(writer, "upstream proxy connection failed", http.StatusBadGateway)
		return
	}
	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", request.Host, request.Host, b.auth); err != nil {
		_ = upstream.Close()
		http.Error(writer, "upstream proxy request failed", http.StatusBadGateway)
		return
	}
	upstreamReader := bufio.NewReader(upstream)
	response, err := http.ReadResponse(upstreamReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = upstream.Close()
		http.Error(writer, "upstream proxy response failed", http.StatusBadGateway)
		return
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		_ = upstream.Close()
		http.Error(writer, "upstream proxy rejected authentication", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(writer, "proxy tunnel is unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, buffered)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, upstreamReader)
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

func (b *authenticatedProxyBridge) forwardHTTP(writer http.ResponseWriter, request *http.Request) {
	upstream, err := net.DialTimeout("tcp", b.upstream, 15*time.Second)
	if err != nil {
		http.Error(writer, "upstream proxy connection failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	forwarded := request.Clone(request.Context())
	forwarded.RequestURI = ""
	forwarded.Header = request.Header.Clone()
	forwarded.Header.Set("Proxy-Authorization", b.auth)
	forwarded.Header.Set("Proxy-Connection", "Keep-Alive")
	if err := forwarded.WriteProxy(upstream); err != nil {
		http.Error(writer, "upstream proxy request failed", http.StatusBadGateway)
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(upstream), forwarded)
	if err != nil {
		http.Error(writer, "upstream proxy response failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}
