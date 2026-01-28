package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

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
