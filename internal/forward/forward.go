package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"socksforward/internal/config"
	"socksforward/pkg/socks5"
)

type Manager struct {
	mu         sync.Mutex
	runners    map[string]*ruleRunner
	lastErrors map[string]string
}

func NewManager() *Manager {
	return &Manager{
		runners:    make(map[string]*ruleRunner),
		lastErrors: make(map[string]string),
	}
}

func (m *Manager) GetRuleError(ruleID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErrors[ruleID]
}

func (m *Manager) Apply(cfg *config.Config) {
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
	nodes := make(map[string]config.Socks5Node)
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
		runner, err := startRule(rule, node)
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
	rule   config.ForwardRule
}

func (r *ruleRunner) Stop() {
	if r == nil {
		return
	}
	r.cancel()
	r.wg.Wait()
}

func startRule(rule config.ForwardRule, node config.Socks5Node) (*ruleRunner, error) {
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
			serveUDP(ctx, conn, rule, node)
		}()
	}

	if proto != "tcp" && proto != "udp" && proto != "both" {
		cancel()
		return nil, errors.New("proto 仅支持 tcp/udp/both")
	}
	log.Printf("规则已启动: %s %s %s -> %s (节点: %s)", rule.ID, rule.Proto, rule.Listen, rule.Target, node.ID)
	return runner, nil
}

func acceptTCP(ctx context.Context, ln net.Listener, rule config.ForwardRule, node config.Socks5Node) {
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

func handleTCP(conn net.Conn, rule config.ForwardRule, node config.Socks5Node) {
	defer conn.Close()
	auth := nodeAuth(node)
	proxyConn, err := socks5.DialTCP(node.Address, rule.Target, auth, 10*time.Second)
	if err != nil {
		log.Printf("TCP 连接失败: %v", err)
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

func serveUDP(ctx context.Context, conn *net.UDPConn, rule config.ForwardRule, node config.Socks5Node) {
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				expired := time.Now().Add(-2 * time.Minute)
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
		if !ok {
			newSess, err := newUDPSession(addr, rule, node, conn)
			if err != nil {
				log.Printf("UDP 创建会话失败: %v", err)
				continue
			}
			mu.Lock()
			sessions[key] = newSess
			sess = newSess
			mu.Unlock()
		}
		sess.lastActive = time.Now()
		packet, err := socks5.EncodeUDPRequest(rule.Target, payload)
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

func newUDPSession(clientAddr *net.UDPAddr, rule config.ForwardRule, node config.Socks5Node, listener *net.UDPConn) (*udpSession, error) {
	auth := nodeAuth(node)
	tcpConn, relayAddr, err := socks5.UDPAssociate(node.Address, auth, 10*time.Second)
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
	go relayToClient(sess, rule, listener)
	return sess, nil
}

func relayToClient(sess *udpSession, rule config.ForwardRule, listener *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := sess.relayConn.Read(buf)
		if err != nil {
			sess.close()
			return
		}
		payload, _, err := socks5.DecodeUDPResponse(buf[:n])
		if err != nil {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		_, _ = listener.WriteToUDP(payload, sess.clientAddr)
	}
}

func nodeAuth(node config.Socks5Node) *socks5.Auth {
	if node.Username == "" && node.Password == "" {
		return nil
	}
	return &socks5.Auth{
		Username: node.Username,
		Password: node.Password,
	}
}
