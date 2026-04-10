package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	webPort := flag.Int("port", 8080, "Web 管理端口")
	configPath := flag.String("config", "config.json", "配置文件路径")
	defaultPassword := flag.String("password", "123456", "Web 管理密码")
	udpTimeout := flag.Int("timeout", 30, "UDP 会话空闲超时时间(秒)")
	flag.Parse()

	if *defaultPassword == "" {
		log.Fatal("默认密码不能为空")
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	manager := NewManager(time.Duration(*udpTimeout) * time.Second)
	manager.Apply(cfg)

	server := NewServer(cfg, *configPath, manager, *defaultPassword)
	addr := fmt.Sprintf("0.0.0.0:%d", *webPort)
	log.Printf("Web 管理监听: %s", addr)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatalf("Web 服务启动失败: %v", err)
	}
}

type Config struct {
	Socks5  Socks5Config  `json:"socks5"`
	Forward ForwardConfig `json:"forward"`
}

type Socks5Config struct {
	Nodes []Socks5Node `json:"nodes"`
}

type Socks5Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ForwardConfig struct {
	Rules []ForwardRule `json:"rules"`
}

type ForwardRule struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Proto        string `json:"proto"`
	Listen       string `json:"listen"`
	Target       string `json:"target"`
	Socks5NodeID string `json:"socks5NodeId"`
	Enabled      bool   `json:"enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		Socks5: Socks5Config{
			Nodes: []Socks5Node{},
		},
		Forward: ForwardConfig{
			Rules: []ForwardRule{},
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		cfg := DefaultConfig()
		if err := SaveConfig(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	if len(b) == 0 {
		cfg := DefaultConfig()
		if err := SaveConfig(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}

	if cfg.Socks5.Nodes == nil {
		cfg.Socks5.Nodes = []Socks5Node{}
	}
	if cfg.Forward.Rules == nil {
		cfg.Forward.Rules = []ForwardRule{}
	}
	return cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func CloneConfig(cfg *Config) *Config {
	if cfg == nil {
		return DefaultConfig()
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return DefaultConfig()
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return DefaultConfig()
	}
	return &out
}

type Auth struct {
	Username string
	Password string
}

func DialTCP(proxyAddr, targetAddr string, auth *Auth, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	if err := Handshake(conn, auth); err != nil {
		conn.Close()
		return nil, err
	}
	if err := Connect(conn, targetAddr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func UDPAssociate(proxyAddr string, auth *Auth, timeout time.Duration) (net.Conn, *net.UDPAddr, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, nil, err
	}
	if err := Handshake(conn, auth); err != nil {
		conn.Close()
		return nil, nil, err
	}
	relayAddr, err := Associate(conn, "0.0.0.0:0")
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, relayAddr, nil
}

func Handshake(conn net.Conn, auth *Auth) error {
	methods := []byte{0x00}
	if auth != nil && auth.Username != "" {
		methods = []byte{0x02}
	}
	req := []byte{0x05, byte(len(methods))}
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return errors.New("SOCKS5 版本不支持")
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		return authUserPass(conn, auth)
	default:
		return errors.New("SOCKS5 认证方式不支持")
	}
}

func Connect(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	if err := writeAddr(&buf, host, port); err != nil {
		return err
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return readReply(conn)
}

func Associate(conn net.Conn, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x03)
	buf.WriteByte(0x00)
	if err := writeAddr(&buf, host, port); err != nil {
		return nil, err
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return readUDPReply(conn)
}

func EncodeUDPRequest(targetAddr string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00, 0x00})
	if err := writeAddr(&buf, host, port); err != nil {
		return nil, err
	}
	buf.Write(payload)
	return buf.Bytes(), nil
}

func DecodeUDPResponse(b []byte) ([]byte, string, error) {
	if len(b) < 4 {
		return nil, "", errors.New("UDP 响应过短")
	}
	if b[2] != 0x00 {
		return nil, "", errors.New("UDP FRAG 不支持")
	}
	r := bytes.NewReader(b[3:])
	addr, err := readAddrPort(r)
	if err != nil {
		return nil, "", err
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	return rest, addr, nil
}

func authUserPass(conn net.Conn, auth *Auth) error {
	if auth == nil {
		return errors.New("需要用户名密码")
	}
	if len(auth.Username) > 255 || len(auth.Password) > 255 {
		return errors.New("用户名或密码过长")
	}
	req := []byte{0x01, byte(len(auth.Username))}
	req = append(req, []byte(auth.Username)...)
	req = append(req, byte(len(auth.Password)))
	req = append(req, []byte(auth.Password)...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("用户名密码认证失败")
	}
	return nil
}

func writeAddr(buf *bytes.Buffer, host string, port int) error {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		if len(host) > 255 {
			return errors.New("域名过长")
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	buf.Write(p)
	return nil
}

func normalizeListenAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("listen 不能为空")
	}
	if port, err := normalizePort(raw); err == nil {
		return ":" + port, nil
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		port, err = normalizePort(port)
		if err != nil {
			return "", err
		}
		if host == "" {
			return ":" + port, nil
		}
		return net.JoinHostPort(host, port), nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return "", errors.New("listen 必须包含端口")
	}
	return "", errors.New("listen 必须为端口号或 host:port")
}

func normalizePort(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("端口不能为空")
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("端口无效")
	}
	return strconv.Itoa(port), nil
}

func formatListenForInput(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, ":") {
		return raw
	}
	port, err := normalizePort(strings.TrimPrefix(raw, ":"))
	if err != nil {
		return raw
	}
	return port
}

func readReply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return errors.New("SOCKS5 响应版本错误")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 连接失败: %d", head[1])
	}
	_, err := readAddrPortFrom(conn, head[3])
	return err
}

func readUDPReply(conn net.Conn) (*net.UDPAddr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[0] != 0x05 {
		return nil, errors.New("SOCKS5 响应版本错误")
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP 关联失败: %d", head[1])
	}
	addr, err := readAddrPortFrom(conn, head[3])
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", addr)
}

func readAddrPortFrom(r io.Reader, atyp byte) (string, error) {
	host, port, err := readAddrPortWithAtyp(r, atyp)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readAddrPort(r io.Reader) (string, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", err
	}
	host, port, err := readAddrPortWithAtyp(r, atyp[0])
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readAddrPortWithAtyp(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	default:
		return "", 0, errors.New("地址类型不支持")
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))
	return host, port, nil
}

type Manager struct {
	mu         sync.Mutex
	runners    map[string]*ruleRunner
	lastErrors map[string]string
	udpTimeout time.Duration
}

func NewManager(udpTimeout time.Duration) *Manager {
	return &Manager{
		runners:    make(map[string]*ruleRunner),
		lastErrors: make(map[string]string),
		udpTimeout: udpTimeout,
	}
}

func (m *Manager) GetRuleError(ruleID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErrors[ruleID]
}

func (m *Manager) Apply(cfg *Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, runner := range m.runners {
		runner.Stop()
		log.Printf("规则已停止: %s %s %s -> %s (节点: %s)", runner.rule.ID, runner.rule.Proto, runner.rule.Listen, runner.rule.Target, runner.rule.Socks5NodeID)
	}
	m.runners = make(map[string]*ruleRunner)
	m.lastErrors = make(map[string]string)
	if cfg == nil {
		return
	}
	nodes := make(map[string]Socks5Node)
	for _, node := range cfg.Socks5.Nodes {
		nodes[node.ID] = node
	}
	for _, rule := range cfg.Forward.Rules {
		if !rule.Enabled {
			continue
		}
		node, ok := nodes[rule.Socks5NodeID]
		if !ok {
			msg := fmt.Sprintf("未找到 SOCKS5 节点: %s", rule.Socks5NodeID)
			log.Printf("规则 %s 错误: %s", rule.ID, msg)
			m.lastErrors[rule.ID] = msg
			continue
		}
		runner, err := startRule(rule, node, m.udpTimeout)
		if err != nil {
			log.Printf("规则 %s 启动失败: %v", rule.ID, err)
			m.lastErrors[rule.ID] = err.Error()
			continue
		}
		m.runners[rule.ID] = runner
	}
}

type ruleRunner struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	rule   ForwardRule
}

func (r *ruleRunner) Stop() {
	if r == nil {
		return
	}
	r.cancel()
	r.wg.Wait()
}

func startRule(rule ForwardRule, node Socks5Node, udpTimeout time.Duration) (*ruleRunner, error) {
	if rule.Listen == "" || rule.Target == "" {
		return nil, errors.New("listen 或 target 为空")
	}
	if rule.Proto == "" {
		return nil, errors.New("proto 为空")
	}
	proto := strings.ToLower(rule.Proto)
	ctx, cancel := context.WithCancel(context.Background())
	runner := &ruleRunner{cancel: cancel, rule: rule}

	if proto == "tcp" || proto == "both" {
		ln, err := net.Listen("tcp", rule.Listen)
		if err != nil {
			cancel()
			return nil, err
		}
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			<-ctx.Done()
			ln.Close()
		}()
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			acceptTCP(ctx, ln, rule, node)
		}()
	}

	if proto == "udp" || proto == "both" {
		udpAddr, err := net.ResolveUDPAddr("udp", rule.Listen)
		if err != nil {
			cancel()
			return nil, err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			cancel()
			return nil, err
		}
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			<-ctx.Done()
			conn.Close()
		}()
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			serveUDP(ctx, conn, rule, node, udpTimeout)
		}()
	}

	if proto != "tcp" && proto != "udp" && proto != "both" {
		cancel()
		return nil, errors.New("proto 仅支持 tcp/udp/both")
	}
	log.Printf("规则已启动: %s %s %s -> %s (节点: %s)", rule.ID, rule.Proto, rule.Listen, rule.Target, node.ID)
	return runner, nil
}

func acceptTCP(ctx context.Context, ln net.Listener, rule ForwardRule, node Socks5Node) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TCP 接受失败: %v", err)
				continue
			}
		}
		go handleTCP(conn, rule, node)
	}
}

func handleTCP(conn net.Conn, rule ForwardRule, node Socks5Node) {
	defer conn.Close()
	sourceAddr := conn.RemoteAddr().String()
	log.Printf("TCP请求 协议=%s 来源=%s 规则=%s 监听=%s 目标=%s 节点=%s", rule.Proto, sourceAddr, rule.Name, rule.Listen, rule.Target, node.Name)
	auth := nodeAuth(node)
	proxyConn, err := DialTCP(node.Address, rule.Target, auth, 10*time.Second)
	if err != nil {
		log.Printf("TCP连接失败 来源=%s 规则=%s 目标=%s 错误=%v", sourceAddr, rule.Name, rule.Target, err)
		return
	}
	defer proxyConn.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(proxyConn, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, proxyConn)
		done <- struct{}{}
	}()
	<-done
}

type udpSession struct {
	clientAddr *net.UDPAddr
	tcpConn    net.Conn
	relayConn  *net.UDPConn
	lastActive time.Time
	closeOnce  sync.Once
	done       chan struct{}
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		if s.relayConn != nil {
			s.relayConn.Close()
		}
		if s.tcpConn != nil {
			s.tcpConn.Close()
		}
		close(s.done)
	})
}

func serveUDP(ctx context.Context, conn *net.UDPConn, rule ForwardRule, node Socks5Node, timeout time.Duration) {
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				expired := time.Now().Add(-timeout)
				mu.Lock()
				for key, sess := range sessions {
					if sess.lastActive.Before(expired) {
						sess.close()
						delete(sessions, key)
					}
				}
				mu.Unlock()
			case <-ctx.Done():
				mu.Lock()
				for key, sess := range sessions {
					sess.close()
					delete(sessions, key)
				}
				mu.Unlock()
				return
			}
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("UDP 读取失败: %v", err)
				continue
			}
		}
		payload := append([]byte(nil), buf[:n]...)
		key := addr.String()
		mu.Lock()
		sess, ok := sessions[key]
		mu.Unlock()

		if ok {
			select {
			case <-sess.done:
				mu.Lock()
				delete(sessions, key)
				mu.Unlock()
				ok = false
			default:
			}
		}

		if !ok {
			newSess, err := newUDPSession(addr, rule, node, conn)
			if err != nil {
				log.Printf("UDP创建会话失败 来源=%s 规则=%s 目标=%s 错误=%v", addr.String(), rule.Name, rule.Target, err)
				continue
			}
			log.Printf("UDP请求 协议=%s 来源=%s 规则=%s 监听=%s 目标=%s 节点=%s", rule.Proto, addr.String(), rule.Name, rule.Listen, rule.Target, node.Name)
			mu.Lock()
			sessions[key] = newSess
			sess = newSess
			mu.Unlock()
		}
		sess.lastActive = time.Now()
		packet, err := EncodeUDPRequest(rule.Target, payload)
		if err != nil {
			log.Printf("UDP 打包失败: %v", err)
			continue
		}
		if _, err := sess.relayConn.Write(packet); err != nil {
			log.Printf("UDP 发送失败: %v", err)
			sess.close()
			mu.Lock()
			delete(sessions, key)
			mu.Unlock()
		}
	}
}

func newUDPSession(clientAddr *net.UDPAddr, rule ForwardRule, node Socks5Node, listener *net.UDPConn) (*udpSession, error) {
	auth := nodeAuth(node)
	tcpConn, relayAddr, err := UDPAssociate(node.Address, auth, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if relayAddr.IP == nil || relayAddr.IP.IsUnspecified() {
		host, _, err := net.SplitHostPort(node.Address)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		resolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(relayAddr.Port)))
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayAddr = resolved
	}
	relayConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	sess := &udpSession{
		clientAddr: clientAddr,
		tcpConn:    tcpConn,
		relayConn:  relayConn,
		lastActive: time.Now(),
		done:       make(chan struct{}),
	}

	// 监控 TCP 连接状态，一旦断开立即终止 UDP 会话
	go func() {
		defer sess.close()
		io.Copy(io.Discard, tcpConn)
	}()

	go relayToClient(sess, rule, listener)
	return sess, nil
}

func relayToClient(sess *udpSession, rule ForwardRule, listener *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := sess.relayConn.Read(buf)
		if err != nil {
			sess.close()
			return
		}
		payload, _, err := DecodeUDPResponse(buf[:n])
		if err != nil {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		_, _ = listener.WriteToUDP(payload, sess.clientAddr)
	}
}

func nodeAuth(node Socks5Node) *Auth {
	if node.Username == "" && node.Password == "" {
		return nil
	}
	return &Auth{
		Username: node.Username,
		Password: node.Password,
	}
}

type Server struct {
	mu         sync.RWMutex
	cfg        *Config
	configPath string
	forward    *Manager
	sessions   map[string]struct{}
	sessionsMu sync.Mutex
	password   string
}

func NewServer(cfg *Config, configPath string, manager *Manager, password string) *Server {
	return &Server{
		cfg:        cfg,
		configPath: configPath,
		forward:    manager,
		sessions:   make(map[string]struct{}),
		password:   password,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("/nodes/add", s.requireAuth(s.handleNodeAdd))
	mux.HandleFunc("/nodes/update", s.requireAuth(s.handleNodeUpdate))
	mux.HandleFunc("/nodes/delete", s.requireAuth(s.handleNodeDelete))
	mux.HandleFunc("/rules/add", s.requireAuth(s.handleRuleAdd))
	mux.HandleFunc("/rules/update", s.requireAuth(s.handleRuleUpdate))
	mux.HandleFunc("/rules/delete", s.requireAuth(s.handleRuleDelete))
	mux.HandleFunc("/rules/toggle", s.requireAuth(s.handleRuleToggle))
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	return s.withMainAccessLog(mux)
}

func (s *Server) withMainAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &mainStatusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		log.Printf("Web请求 类型=%s 方法=%s 路径=%s 来源=%s 状态=%d 耗时=%s",
			classifyMainWebRequest(r),
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			rec.status,
			time.Since(start).Truncate(time.Millisecond),
		)
	})
}

func classifyMainWebRequest(r *http.Request) string {
	switch r.URL.Path {
	case "/login":
		return "web-login"
	case "/logout":
		return "web-logout"
	case "/nodes/add", "/nodes/update", "/nodes/delete":
		return "web-node"
	case "/rules/add", "/rules/update", "/rules/delete", "/rules/toggle":
		return "web-forward-rule"
	case "/":
		return "web-index"
	default:
		return "web-other"
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.isAuthed(r) {
			next(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func (s *Server) isAuthed(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return false
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	_, ok := s.sessions[cookie.Value]
	return ok
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderLogin(w, "表单解析失败")
			return
		}
		password := r.FormValue("password")
		if password != s.password {
			renderLogin(w, "密码错误")
			return
		}
		token, err := newToken()
		if err != nil {
			renderLogin(w, "生成会话失败")
			return
		}
		s.sessionsMu.Lock()
		s.sessions[token] = struct{}{}
		s.sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderLogin(w, "")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	s.mu.RLock()
	ruleErrors := make(map[string]string)
	if s.forward != nil {
		for _, rule := range s.cfg.Forward.Rules {
			if rule.Enabled {
				if err := s.forward.GetRuleError(rule.ID); err != "" {
					ruleErrors[rule.ID] = err
				}
			}
		}
	}
	data := pageData{
		Nodes:      append([]Socks5Node(nil), s.cfg.Socks5.Nodes...),
		Rules:      append([]ForwardRule(nil), s.cfg.Forward.Rules...),
		RuleErrors: ruleErrors,
		Message:    msg,
	}
	s.mu.RUnlock()
	renderIndex(w, data)
}

func (s *Server) handleNodeAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectMsg(w, r, "节点名称不能为空")
		return
	}
	address := strings.TrimSpace(r.FormValue("address"))
	if address == "" {
		redirectMsg(w, r, "节点地址不能为空")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	err := s.updateConfig(func(cfg *Config) error {
		if nodeNameExists(cfg, name, "") {
			return fmt.Errorf("节点名称已存在")
		}
		id, err := newID()
		if err != nil {
			return err
		}
		cfg.Socks5.Nodes = append(cfg.Socks5.Nodes, Socks5Node{
			ID:       id,
			Name:     name,
			Address:  address,
			Username: username,
			Password: password,
		})
		return nil
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "节点已添加")
}

func (s *Server) handleNodeUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	address := strings.TrimSpace(r.FormValue("address"))
	if id == "" || address == "" {
		redirectMsg(w, r, "节点或地址不能为空")
		return
	}
	if name == "" {
		redirectMsg(w, r, "节点名称不能为空")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	err := s.updateConfig(func(cfg *Config) error {
		if nodeNameExists(cfg, name, id) {
			return fmt.Errorf("节点名称已存在")
		}
		for i, node := range cfg.Socks5.Nodes {
			if node.ID == id {
				cfg.Socks5.Nodes[i].Name = name
				cfg.Socks5.Nodes[i].Address = address
				cfg.Socks5.Nodes[i].Username = username
				cfg.Socks5.Nodes[i].Password = password
				return nil
			}
		}
		return fmt.Errorf("节点不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "节点已更新")
}

func (s *Server) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		redirectMsg(w, r, "节点 ID 不能为空")
		return
	}
	err := s.updateConfig(func(cfg *Config) error {
		for _, rule := range cfg.Forward.Rules {
			if rule.Socks5NodeID == id {
				return fmt.Errorf("已有规则使用该节点")
			}
		}
		for i, node := range cfg.Socks5.Nodes {
			if node.ID == id {
				cfg.Socks5.Nodes = append(cfg.Socks5.Nodes[:i], cfg.Socks5.Nodes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("节点不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "节点已删除")
}

func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectMsg(w, r, "规则名称不能为空")
		return
	}
	proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
	listen := strings.TrimSpace(r.FormValue("listen"))
	target := strings.TrimSpace(r.FormValue("target"))
	nodeID := strings.TrimSpace(r.FormValue("socks5NodeId"))
	enabled := r.FormValue("enabled") == "on"
	if listen == "" || target == "" || nodeID == "" {
		redirectMsg(w, r, "规则字段不能为空")
		return
	}
	normalizedListen, err := normalizeListenAddress(listen)
	if err != nil {
		redirectMsg(w, r, "监听地址格式无效，应为端口号或 host:port")
		return
	}
	listen = normalizedListen
	if proto != "tcp" && proto != "udp" && proto != "both" {
		redirectMsg(w, r, "协议仅支持 tcp/udp/both")
		return
	}

	err = s.updateConfig(func(cfg *Config) error {
		if ruleNameExists(cfg, name, "") {
			return fmt.Errorf("规则名称已存在")
		}
		id, err := newID()
		if err != nil {
			return err
		}
		if !nodeExists(cfg, nodeID) {
			return fmt.Errorf("SOCKS5 节点不存在")
		}
		cfg.Forward.Rules = append(cfg.Forward.Rules, ForwardRule{
			ID:           id,
			Name:         name,
			Proto:        proto,
			Listen:       listen,
			Target:       target,
			Socks5NodeID: nodeID,
			Enabled:      enabled,
		})
		return nil
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "规则已添加")
}

func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectMsg(w, r, "规则名称不能为空")
		return
	}
	proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
	listen := strings.TrimSpace(r.FormValue("listen"))
	target := strings.TrimSpace(r.FormValue("target"))
	nodeID := strings.TrimSpace(r.FormValue("socks5NodeId"))
	enabledProvided := r.FormValue("enabled") != ""
	enabled := r.FormValue("enabled") == "on"
	if id == "" || listen == "" || target == "" || nodeID == "" {
		redirectMsg(w, r, "规则字段不能为空")
		return
	}
	normalizedListen, err := normalizeListenAddress(listen)
	if err != nil {
		redirectMsg(w, r, "监听地址格式无效，应为端口号或 host:port")
		return
	}
	listen = normalizedListen
	if proto != "tcp" && proto != "udp" && proto != "both" {
		redirectMsg(w, r, "协议仅支持 tcp/udp/both")
		return
	}
	err = s.updateConfig(func(cfg *Config) error {
		if ruleNameExists(cfg, name, id) {
			return fmt.Errorf("规则名称已存在")
		}
		if !nodeExists(cfg, nodeID) {
			return fmt.Errorf("SOCKS5 节点不存在")
		}
		for i, rule := range cfg.Forward.Rules {
			if rule.ID == id {
				cfg.Forward.Rules[i].Name = name
				cfg.Forward.Rules[i].Proto = proto
				cfg.Forward.Rules[i].Listen = listen
				cfg.Forward.Rules[i].Target = target
				cfg.Forward.Rules[i].Socks5NodeID = nodeID
				if enabledProvided {
					cfg.Forward.Rules[i].Enabled = enabled
				}
				return nil
			}
		}
		return fmt.Errorf("规则不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "规则已更新")
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	err := s.updateConfig(func(cfg *Config) error {
		for i, rule := range cfg.Forward.Rules {
			if rule.ID == id {
				cfg.Forward.Rules = append(cfg.Forward.Rules[:i], cfg.Forward.Rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("规则不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "规则已删除")
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	err := s.updateConfig(func(cfg *Config) error {
		for i, rule := range cfg.Forward.Rules {
			if rule.ID == id {
				cfg.Forward.Rules[i].Enabled = !rule.Enabled
				return nil
			}
		}
		return fmt.Errorf("规则不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	errMsg := ""
	if s.forward != nil {
		if errStr := s.forward.GetRuleError(id); errStr != "" {
			errMsg = " (启动失败: " + errStr + ")"
		}
	}
	redirectMsg(w, r, "规则状态已更新"+errMsg)
}

func (s *Server) updateConfig(fn func(cfg *Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.cfg); err != nil {
		return err
	}
	if err := SaveConfig(s.configPath, s.cfg); err != nil {
		return err
	}
	if s.forward != nil {
		s.forward.Apply(CloneConfig(s.cfg))
	}
	return nil
}

func nodeExists(cfg *Config, nodeID string) bool {
	for _, node := range cfg.Socks5.Nodes {
		if node.ID == nodeID {
			return true
		}
	}
	return false
}

func nodeNameExists(cfg *Config, name string, excludeID string) bool {
	for _, node := range cfg.Socks5.Nodes {
		if node.Name == name && node.ID != excludeID {
			return true
		}
	}
	return false
}

func ruleNameExists(cfg *Config, name string, excludeID string) bool {
	for _, rule := range cfg.Forward.Rules {
		if rule.Name == name && rule.ID != excludeID {
			return true
		}
	}
	return false
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func redirectMsg(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?msg="+url.QueryEscape(msg), http.StatusFound)
}

type mainStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *mainStatusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func mainClientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

type pageData struct {
	Nodes      []Socks5Node
	Rules      []ForwardRule
	RuleErrors map[string]string
	Message    string
}

func renderLogin(w http.ResponseWriter, msg string) {
	tmpl := template.Must(template.New("login").Parse(loginTemplate))
	_ = tmpl.Execute(w, map[string]any{"Message": msg})
}

func renderIndex(w http.ResponseWriter, data pageData) {
	funcs := template.FuncMap{
		"eq":          func(a, b string) bool { return a == b },
		"listenInput": formatListenForInput,
	}
	tmpl := template.Must(template.New("index").Funcs(funcs).Parse(indexTemplate))
	_ = tmpl.Execute(w, data)
}

const loginTemplate = `
<!doctype html>
<html lang="zh" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录</title>
  <style>
    :root {
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --bg: #f3f4f6;
      --bg-accent: linear-gradient(135deg, #eff6ff 0%, #f8fafc 60%, #eef2ff 100%);
      --text: #1f2937;
      --muted: #6b7280;
      --card: #ffffff;
      --border: #e5e7eb;
      --danger: #ef4444;
      --shadow: 0 16px 40px rgba(15, 23, 42, 0.10);
    }
    html[data-theme="dark"] {
      --primary: #60a5fa;
      --primary-hover: #3b82f6;
      --bg: #0f172a;
      --bg-accent: radial-gradient(circle at top, rgba(37, 99, 235, 0.25), transparent 40%), linear-gradient(180deg, #0f172a 0%, #111827 100%);
      --text: #e5e7eb;
      --muted: #94a3b8;
      --card: #111827;
      --border: #334155;
      --danger: #f87171;
      --shadow: 0 18px 48px rgba(2, 6, 23, 0.45);
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg-accent);
      margin: 0;
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      width: 100%;
      max-width: 420px;
      background: var(--card);
      padding: 32px;
      border-radius: 20px;
      box-shadow: var(--shadow);
      border: 1px solid var(--border);
    }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; gap: 12px; }
    h2 { margin: 0; color: var(--text); font-size: 24px; }
    .sub { color: var(--muted); font-size: 14px; margin-bottom: 20px; }
    .field { margin-bottom: 16px; }
    input {
      width: 100%;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      box-sizing: border-box;
      font-size: 15px;
      transition: border-color 0.2s, box-shadow 0.2s;
      background: var(--card);
      color: var(--text);
    }
    input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14); }
    button {
      width: 100%;
      padding: 12px;
      border: none;
      background: var(--primary);
      color: #fff;
      border-radius: 10px;
      cursor: pointer;
      font-size: 15px;
      font-weight: 600;
      transition: background 0.2s;
    }
    button:hover { background: var(--primary-hover); }
    .msg {
      background: rgba(239, 68, 68, 0.12);
      color: var(--danger);
      padding: 12px;
      border-radius: 10px;
      margin-bottom: 20px;
      font-size: 14px;
      text-align: center;
      border: 1px solid rgba(239, 68, 68, 0.28);
    }
    .theme-toggle {
      width: auto;
      padding: 8px 12px;
      background: transparent;
      color: var(--text);
      border: 1px solid var(--border);
      font-size: 13px;
      font-weight: 500;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2>管理登录</h2>
      <button type="button" class="theme-toggle" onclick="toggleTheme()">切换主题</button>
    </div>
    <div class="sub">SocksForward 管理后台</div>
    {{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
    <form method="post" action="/login">
      <div class="field"><input name="password" type="password" placeholder="密码" required autocomplete="current-password"></div>
      <div class="field"><button type="submit">登录</button></div>
    </form>
  </div>
  <script>
    (function() {
      var saved = localStorage.getItem('theme');
      var theme = saved === 'dark' || saved === 'light' ? saved : 'light';
      document.documentElement.setAttribute('data-theme', theme);
    })();
    function toggleTheme() {
      var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
      var next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    }
  </script>
</body>
</html>
`

const indexTemplate = `
<!doctype html>
<html lang="zh" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SocksForward</title>
  <style>
    :root {
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --bg: #f3f4f6;
      --bg-soft: linear-gradient(180deg, #f8fbff 0%, #f3f4f6 100%);
      --panel: #ffffff;
      --panel-soft: #f9fafb;
      --text: #1f2937;
      --text-light: #6b7280;
      --border: #e5e7eb;
      --danger: #ef4444;
      --success: #10b981;
      --warning: #b45309;
      --shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
      --shadow-soft: 0 6px 18px rgba(15, 23, 42, 0.05);
    }
    html[data-theme="dark"] {
      --primary: #60a5fa;
      --primary-hover: #3b82f6;
      --bg: #0f172a;
      --bg-soft: radial-gradient(circle at top, rgba(37, 99, 235, 0.18), transparent 35%), linear-gradient(180deg, #0f172a 0%, #111827 100%);
      --panel: #111827;
      --panel-soft: #172033;
      --text: #e5e7eb;
      --text-light: #94a3b8;
      --border: #334155;
      --danger: #f87171;
      --success: #34d399;
      --warning: #fbbf24;
      --shadow: 0 18px 48px rgba(2, 6, 23, 0.45);
      --shadow-soft: 0 10px 24px rgba(2, 6, 23, 0.32);
    }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: var(--bg-soft); margin: 0; color: var(--text); line-height: 1.5; padding-bottom: 40px; transition: background 0.2s ease, color 0.2s ease; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .topbar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; background: var(--panel); padding: 18px 24px; border-radius: 16px; box-shadow: var(--shadow); margin-bottom: 24px; gap: 16px; border: 1px solid var(--border); }
    .user-info { font-weight: 500; color: var(--text); display: flex; align-items: center; gap: 8px; }
    .user-title { font-size: 22px; font-weight: 700; letter-spacing: 0.2px; }
    .user-subtitle { color: var(--text-light); font-size: 13px; margin-top: 4px; }
    .card { background: var(--panel); padding: 24px; border-radius: 18px; box-shadow: var(--shadow-soft); margin-bottom: 24px; overflow: hidden; border: 1px solid var(--border); }
    h3 { margin: 0; font-size: 18px; color: #111827; }
    html[data-theme="dark"] h3 { color: var(--text); }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin: 0 0 20px 0; padding: 0; flex-wrap: wrap; gap: 8px; }
    .section-header.sub { margin: 24px 0 16px 0; }
    .hint { font-size: 13px; color: var(--text-light); font-weight: normal; background: var(--panel-soft); padding: 5px 10px; border-radius: 999px; border: 1px solid var(--border); }
    .theme-switch { display: flex; gap: 8px; flex-wrap: wrap; }
    input, select { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; font-size: 14px; transition: border-color 0.2s, box-shadow 0.2s, background 0.2s; background: var(--panel); color: var(--text); min-width: 0; }
    input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
    .form-grid { display: grid; gap: 0; margin-bottom: 16px; align-items: start; border-collapse: separate; border-spacing: 0; }
    .field { min-width: 0; overflow: hidden; padding: 16px; background: var(--panel); border-bottom: 1px solid var(--border); }
    .field:last-child { border-bottom: none; }
    .field-header { min-width: 0; overflow: hidden; padding: 12px 16px; background: var(--panel-soft); border-bottom: 1px solid var(--border); }
    .field-header .field-label { margin: 0; text-transform: uppercase; letter-spacing: 0.5px; }
    .node-add-grid { grid-template-columns: 18% 28% 18% 18% 18%; }
    .rule-add-grid { grid-template-columns: 16% 14% 13% 22% 15% 20%; }
    .form-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .form-row.space-between { justify-content: space-between; }
    .form-submit { justify-self: stretch; width: 100%; display: flex; justify-content: flex-start; align-items: center; }
    .form-submit button { width: auto; max-width: none; }
    .field-label { display: block; margin-bottom: 6px; font-size: 13px; font-weight: 600; color: var(--text-light); }
    .field input, .field select { margin: 0; }
    select {
      padding-right: 48px;
      text-overflow: ellipsis;
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      background-image:
        linear-gradient(45deg, transparent 50%, var(--text-light) 50%),
        linear-gradient(135deg, var(--text-light) 50%, transparent 50%);
      background-position:
        calc(100% - 18px) calc(50% - 2px),
        calc(100% - 12px) calc(50% - 2px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
    }
    select::-ms-expand { display: none; }
    label { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 14px; user-select: none; }
    input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--primary); margin: 0; }
    button { height: 38px; padding: 0 16px; border: none; background: var(--primary); color: #ffffff; border-radius: 10px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; }
    button:hover { background: var(--primary-hover); }
    button:active { transform: translateY(1px); }
    .btn-secondary { background: #6b7280; }
    .btn-secondary:hover { background: #4b5563; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    .btn-success { background: var(--success); }
    .btn-success:hover { background: #059669; }
    .btn-sm { height: 32px; padding: 0 10px; font-size: 13px; }
    .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
    .btn-outline:hover { background: var(--panel-soft); }
    .btn-outline.active { background: var(--primary); color: #fff; border-color: var(--primary); }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .action-cell { vertical-align: middle; }
    .action-stack { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .action-stack.inline { flex-wrap: wrap; }
    .action-stack form { margin: 0; display: flex; }
    .action-stack.inline form { flex: 0 0 auto; }
    .action-stack.inline .btn-sm { min-width: 56px; }
    .action-stack .rule-error { width: 100%; }
    .msg { background: rgba(16, 185, 129, 0.12); color: #047857; padding: 12px 16px; border-radius: 12px; margin-bottom: 24px; border: 1px solid rgba(16, 185, 129, 0.28); display: flex; align-items: center; }
    html[data-theme="dark"] .msg { color: #6ee7b7; }
    .table-wrap { overflow-x: hidden; }
    table { width: 100%; border-collapse: separate; border-spacing: 0; }
    .table-fixed { table-layout: fixed; }
    th { text-align: left; padding: 12px 16px; background: var(--panel-soft); font-weight: 600; font-size: 13px; color: var(--text-light); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
    td { padding: 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    td input, td select { min-width: 0; }
    tr:last-child td { border-bottom: none; }
    .rule-error { display: block; margin-top: 8px; color: var(--warning); font-size: 12px; white-space: normal; word-break: break-word; }
    .grid-note { color: var(--text-light); font-size: 12px; margin-top: -6px; margin-bottom: 14px; }
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; justify-content: center; align-items: center; z-index: 1000; }
    .modal { background: var(--panel); padding: 24px; border-radius: 12px; width: 90%; max-width: 400px; box-shadow: var(--shadow); border: 1px solid var(--border); }
    .modal-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; color: var(--text); }
    .modal-body { margin-bottom: 24px; color: var(--text-light); font-size: 14px; line-height: 1.5; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 12px; }
    @media (max-width: 768px) {
      body { padding: 10px; padding-bottom: 80px; }
      .container { padding: 0; }
      .topbar { padding: 12px 16px; flex-direction: column; align-items: stretch; text-align: center; }
      .user-info { justify-content: center; margin-bottom: 8px; flex-direction: column; }
      .card { padding: 16px; border-radius: 12px; }
      table, thead, tbody, th, td, tr { display: block; }
      thead tr { position: absolute; top: -9999px; left: -9999px; }
      tr { margin-bottom: 16px; border: 1px solid var(--border); border-radius: 12px; background: var(--panel); box-shadow: 0 1px 2px rgba(0,0,0,0.05); overflow: hidden; }
      tr:last-child { margin-bottom: 0; }
      td { border: none; border-bottom: 1px solid #f3f4f6; position: relative; padding: 12px 16px; padding-left: 35%; display: flex; align-items: center; flex-wrap: wrap; min-height: 48px; }
      td:last-child { border-bottom: none; padding-left: 16px; justify-content: flex-end; background: var(--panel-soft); }
      td::before { position: absolute; left: 16px; width: 30%; white-space: nowrap; font-weight: 600; font-size: 13px; color: var(--text-light); content: attr(data-label); }
      .form-grid, .node-add-grid, .rule-add-grid { grid-template-columns: 1fr; }
      .form-submit { justify-self: stretch; }
      .form-submit button { max-width: none; }
      .theme-switch { justify-content: center; }
      .action-stack.inline { flex-wrap: wrap; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="user-info">
        <div>
          <div class="user-title">SocksForward</div>
          <div class="user-subtitle">SOCKS5 节点与 TCP/UDP 转发规则管理</div>
        </div>
      </div>
      <div class="actions">
        <div class="theme-switch">
          <button type="button" class="btn-outline btn-sm" id="btn-light" onclick="setTheme('light')">日间模式</button>
          <button type="button" class="btn-outline btn-sm" id="btn-dark" onclick="setTheme('dark')">夜间模式</button>
        </div>
        <button onclick="window.location.href = window.location.pathname" class="btn-success btn-sm">刷新</button>
        <form method="post" action="/logout"><button type="submit" class="btn-secondary btn-sm">退出登录</button></form>
      </div>
    </div>
    {{if .Message}}<div class="msg">{{.Message}}</div>{{end}}

    <div class="card">
      <div class="section-header">
        <h3>SOCKS5 节点</h3>
        <span class="hint">名称唯一，系统自动生成 ID</span>
      </div>
      <div class="table-wrap">
      <table class="table-fixed">
        <colgroup>
          <col style="width:18%">
          <col style="width:28%">
          <col style="width:18%">
          <col style="width:18%">
          <col style="width:18%">
        </colgroup>
        <thead>
          <tr><th>名称</th><th>地址</th><th>用户名</th><th>密码</th><th>操作</th></tr>
        </thead>
        <tbody>
          {{range .Nodes}}
          <tr>
            <form method="post" action="/nodes/update" style="margin:0">
              <td data-label="名称"><input type="hidden" name="id" value="{{.ID}}"><input name="name" value="{{.Name}}" required placeholder="节点名称"></td>
              <td data-label="地址"><input name="address" value="{{.Address}}" required placeholder="127.0.0.1:1080"></td>
              <td data-label="用户名"><input name="username" value="{{.Username}}" placeholder="可选"></td>
              <td data-label="密码"><input name="password" type="password" value="{{.Password}}" placeholder="可选"></td>
              <td class="action-cell" data-label="操作">
                <div class="action-stack inline">
                  <button type="submit" class="btn-sm">保存</button>
            </form>
                  <form method="post" action="/nodes/delete" style="margin:0" onsubmit="confirmDelete(event, this)">
                    <input type="hidden" name="id" value="{{.ID}}">
                    <button type="submit" class="btn-danger btn-sm">删除</button>
                  </form>
                </div>
              </td>
          </tr>
          {{else}}
          <tr><td colspan="5">暂无节点，请先添加 SOCKS5 节点。</td></tr>
          {{end}}
        </tbody>
      </table>
      </div>

      <div class="section-header sub">
        <h3>新增节点</h3>
      </div>
      <form method="post" action="/nodes/add">
        <div class="form-grid node-add-grid">
          <div class="field-header"><span class="field-label">名称</span></div>
          <div class="field-header"><span class="field-label">地址</span></div>
          <div class="field-header"><span class="field-label">用户名</span></div>
          <div class="field-header"><span class="field-label">密码</span></div>
          <div class="field-header"><span class="field-label">操作</span></div>
          <div class="field"><input name="name" placeholder="节点名称" required></div>
          <div class="field"><input name="address" placeholder="127.0.0.1:1080" required></div>
          <div class="field"><input name="username" placeholder="可选"></div>
          <div class="field"><input name="password" type="password" placeholder="可选"></div>
          <div class="field form-submit"><button type="submit">添加节点</button></div>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="section-header">
        <h3>转发规则</h3>
        <span class="hint">支持 TCP、UDP、Both，本地监听支持直接填端口号</span>
      </div>
      <div class="table-wrap">
      <table class="table-fixed">
        <colgroup>
          <col style="width:16%">
          <col style="width:14%">
          <col style="width:13%">
          <col style="width:22%">
          <col style="width:15%">
          <col style="width:20%">
        </colgroup>
        <thead>
          <tr><th>名称</th><th>协议</th><th>监听</th><th>目标</th><th>节点</th><th>操作</th></tr>
        </thead>
        <tbody>
          {{range .Rules}}
          {{$rule := .}}
          <tr>
            <form method="post" action="/rules/update" style="margin:0">
              <td data-label="名称"><input type="hidden" name="id" value="{{.ID}}"><input name="name" value="{{.Name}}" required placeholder="规则名称"></td>
              <td data-label="协议">
                <select name="proto">
                  <option value="tcp" {{if eq .Proto "tcp"}}selected{{end}}>TCP</option>
                  <option value="udp" {{if eq .Proto "udp"}}selected{{end}}>UDP</option>
                  <option value="both" {{if eq .Proto "both"}}selected{{end}}>Both</option>
                </select>
              </td>
              <td data-label="监听"><input name="listen" value="{{listenInput .Listen}}" required placeholder="8080"></td>
              <td data-label="目标"><input name="target" value="{{.Target}}" required placeholder="example.com:443"></td>
              <td data-label="节点">
                <select name="socks5NodeId" required>
                  {{range $.Nodes}}
                  <option value="{{.ID}}" {{if eq .ID $rule.Socks5NodeID}}selected{{end}}>{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</option>
                  {{end}}
                </select>
              </td>
              <td class="action-cell" data-label="操作">
                <div class="action-stack inline">
                  <button type="submit" class="btn-sm">保存</button>
            </form>
                  <form method="post" action="/rules/toggle" style="margin:0">
                    <input type="hidden" name="id" value="{{.ID}}">
                    {{if .Enabled}}
                      {{if index $.RuleErrors .ID}}
                        <button type="submit" class="btn-danger btn-sm">启动失败</button>
                      {{else}}
                        <button type="submit" class="btn-success btn-sm">已启用</button>
                      {{end}}
                    {{else}}
                      <button type="submit" class="btn-secondary btn-sm">已停用</button>
                    {{end}}
                  </form>
                  <form method="post" action="/rules/delete" style="margin:0" onsubmit="confirmDelete(event, this)">
                    <input type="hidden" name="id" value="{{.ID}}">
                    <button type="submit" class="btn-danger btn-sm">删除</button>
                  </form>
                  {{if index $.RuleErrors .ID}}<span class="rule-error">{{index $.RuleErrors .ID}}</span>{{end}}
                </div>
              </td>
          </tr>
          {{else}}
          <tr><td colspan="6">暂无转发规则。</td></tr>
          {{end}}
        </tbody>
      </table>
      </div>

      <div class="section-header sub">
        <h3>新增转发规则</h3>
      </div>
      <form method="post" action="/rules/add">
        <div class="form-grid rule-add-grid">
          <div class="field-header"><span class="field-label">名称</span></div>
          <div class="field-header"><span class="field-label">协议</span></div>
          <div class="field-header"><span class="field-label">监听</span></div>
          <div class="field-header"><span class="field-label">目标</span></div>
          <div class="field-header"><span class="field-label">节点</span></div>
          <div class="field-header"><span class="field-label">操作</span></div>
          <div class="field"><input name="name" placeholder="规则名称" required></div>
          <div class="field">
            <select name="proto" required>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">Both</option>
            </select>
          </div>
          <div class="field"><input name="listen" placeholder="8443" required></div>
          <div class="field"><input name="target" placeholder="example.com:443" required></div>
          <div class="field">
            <select name="socks5NodeId" required>
              {{range .Nodes}}<option value="{{.ID}}">{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</option>{{end}}
            </select>
          </div>
          <div class="field form-submit"><button type="submit">添加规则</button></div>
        </div>
        <div class="grid-note">监听支持直接填写端口号，例如 8443 会按 :8443 监听；也支持 127.0.0.1:8443 这种写法。</div>
        <div class="form-row space-between">
          <label><input type="checkbox" name="enabled" checked> 立即启用</label>
        </div>
      </form>
    </div>
  </div>

  <div class="modal-overlay" id="confirmModal">
    <div class="modal">
      <div class="modal-title">确认操作</div>
      <div class="modal-body" id="confirmMessage">确定要执行此操作吗？</div>
      <div class="modal-actions">
        <button class="btn-secondary" onclick="closeModal()">取消</button>
        <button class="btn-danger" id="confirmBtn">确定</button>
      </div>
    </div>
  </div>

  <script>
    let pendingForm = null;
    const modal = document.getElementById('confirmModal');
    const msgElem = document.getElementById('confirmMessage');
    const confirmBtn = document.getElementById('confirmBtn');

    (function() {
      var saved = localStorage.getItem('theme');
      var theme = saved === 'dark' || saved === 'light' ? saved : 'light';
      document.documentElement.setAttribute('data-theme', theme);
      updateThemeButtons(theme);

      var scrollPos = sessionStorage.getItem('scrollPos');
      if (scrollPos) {
        window.scrollTo(0, parseInt(scrollPos, 10) || 0);
        sessionStorage.removeItem('scrollPos');
      }
    })();

    function updateThemeButtons(theme) {
      var light = document.getElementById('btn-light');
      var dark = document.getElementById('btn-dark');
      if (light && dark) {
        light.classList.toggle('active', theme === 'light');
        dark.classList.toggle('active', theme === 'dark');
      }
    }

    function setTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('theme', theme);
      updateThemeButtons(theme);
    }

    function confirmDelete(e, form) {
      e.preventDefault();
      pendingForm = form;
      msgElem.textContent = '确定要删除吗？此操作无法撤销。';
      modal.style.display = 'flex';
    }

    function closeModal() {
      modal.style.display = 'none';
      pendingForm = null;
    }

    confirmBtn.onclick = function() {
      if (pendingForm) {
        pendingForm.submit();
      }
      closeModal();
    };

    modal.onclick = function(e) {
      if (e.target === modal) closeModal();
    }

    document.addEventListener('submit', function() {
      sessionStorage.setItem('scrollPos', String(window.scrollY || 0));
    }, true);

    window.addEventListener('beforeunload', function() {
      sessionStorage.setItem('scrollPos', String(window.scrollY || 0));
    });
  </script>
</body>
</html>
`
