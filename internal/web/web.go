package web

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"socksforward/internal/config"
	"socksforward/internal/forward"
)

type Server struct {
	mu         sync.RWMutex
	cfg        *config.Config
	configPath string
	forward    *forward.Manager
	sessions   map[string]struct{}
	sessionsMu sync.Mutex
}

func NewServer(cfg *config.Config, configPath string, manager *forward.Manager) *Server {
	return &Server{
		cfg:        cfg,
		configPath: configPath,
		forward:    manager,
		sessions:   make(map[string]struct{}),
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
	mux.HandleFunc("/password", s.requireAuth(s.handlePassword))
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	return mux
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
		s.mu.RLock()
		ok := config.VerifyPassword(s.cfg, password)
		s.mu.RUnlock()
		if !ok {
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
		Nodes:      append([]config.Socks5Node(nil), s.cfg.Socks5.Nodes...),
		Rules:      append([]config.ForwardRule(nil), s.cfg.Forward.Rules...),
		RuleErrors: ruleErrors,
		Message:    msg,
	}
	s.mu.RUnlock()
	renderIndex(w, data)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	oldPass := r.FormValue("oldPassword")
	newPass := r.FormValue("newPassword")
	if newPass == "" {
		redirectMsg(w, r, "新密码不能为空")
		return
	}
	err := s.updateConfig(func(cfg *config.Config) error {
		if !config.VerifyPassword(cfg, oldPass) {
			return fmt.Errorf("旧密码错误")
		}
		return config.UpdatePassword(cfg, newPass)
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "密码已更新")
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

	err := s.updateConfig(func(cfg *config.Config) error {
		if nodeNameExists(cfg, name, "") {
			return fmt.Errorf("节点名称已存在")
		}
		id, err := newID()
		if err != nil {
			return err
		}
		cfg.Socks5.Nodes = append(cfg.Socks5.Nodes, config.Socks5Node{
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

	err := s.updateConfig(func(cfg *config.Config) error {
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
	err := s.updateConfig(func(cfg *config.Config) error {
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
	if proto != "tcp" && proto != "udp" && proto != "both" {
		redirectMsg(w, r, "协议仅支持 tcp/udp/both")
		return
	}

	err := s.updateConfig(func(cfg *config.Config) error {
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
		cfg.Forward.Rules = append(cfg.Forward.Rules, config.ForwardRule{
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
	if proto != "tcp" && proto != "udp" && proto != "both" {
		redirectMsg(w, r, "协议仅支持 tcp/udp/both")
		return
	}
	err := s.updateConfig(func(cfg *config.Config) error {
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
	err := s.updateConfig(func(cfg *config.Config) error {
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
	err := s.updateConfig(func(cfg *config.Config) error {
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

func (s *Server) updateConfig(fn func(cfg *config.Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.cfg); err != nil {
		return err
	}
	if err := config.Save(s.configPath, s.cfg); err != nil {
		return err
	}
	if s.forward != nil {
		s.forward.Apply(config.Clone(s.cfg))
	}
	return nil
}

func nodeExists(cfg *config.Config, nodeID string) bool {
	for _, node := range cfg.Socks5.Nodes {
		if node.ID == nodeID {
			return true
		}
	}
	return false
}

func nodeNameExists(cfg *config.Config, name string, excludeID string) bool {
	for _, node := range cfg.Socks5.Nodes {
		if node.Name == name && node.ID != excludeID {
			return true
		}
	}
	return false
}

func ruleNameExists(cfg *config.Config, name string, excludeID string) bool {
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

type pageData struct {
	Nodes      []config.Socks5Node
	Rules      []config.ForwardRule
	RuleErrors map[string]string
	Message    string
}

func renderLogin(w http.ResponseWriter, msg string) {
	tmpl := template.Must(template.New("login").Parse(loginTemplate))
	_ = tmpl.Execute(w, map[string]any{"Message": msg})
}

func renderIndex(w http.ResponseWriter, data pageData) {
	funcs := template.FuncMap{
		"eq": func(a, b string) bool { return a == b },
	}
	tmpl := template.Must(template.New("index").Funcs(funcs).Parse(indexTemplate))
	_ = tmpl.Execute(w, data)
}

const loginTemplate = `
<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录</title>
  <style>
    :root { --primary: #2563eb; --bg: #f3f4f6; --text: #1f2937; --white: #ffffff; --border: #e5e7eb; --danger: #ef4444; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: var(--bg); margin: 0; color: var(--text); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; box-sizing: border-box; }
    .container { width: 100%; max-width: 400px; background: var(--white); padding: 32px; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); }
    h2 { margin-top: 0; text-align: center; color: #111827; margin-bottom: 24px; font-size: 24px; }
    .field { margin-bottom: 16px; }
    input { width: 100%; padding: 12px; border: 1px solid var(--border); border-radius: 8px; box-sizing: border-box; font-size: 16px; transition: border-color 0.2s; }
    input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
    button { width: 100%; padding: 12px; border: none; background: var(--primary); color: var(--white); border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 500; transition: background 0.2s; }
    button:hover { background: #1d4ed8; }
    .msg { background: #fef2f2; color: var(--danger); padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; text-align: center; border: 1px solid #fee2e2; }
  </style>
</head>
<body>
  <div class="container">
    <h2>管理登录</h2>
    {{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
    <form method="post" action="/login">
      <div class="field"><input name="password" type="password" placeholder="密码" required autocomplete="current-password"></div>
      <div class="field"><button type="submit">登录</button></div>
    </form>
  </div>
</body>
</html>
`

const indexTemplate = `
<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SocksForward</title>
  <style>
    :root { --primary: #2563eb; --primary-hover: #1d4ed8; --bg: #f3f4f6; --text: #1f2937; --text-light: #6b7280; --white: #ffffff; --border: #e5e7eb; --danger: #ef4444; --success: #10b981; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: var(--bg); margin: 0; color: var(--text); line-height: 1.5; padding-bottom: 40px; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    
    /* Topbar */
    .topbar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; background: var(--white); padding: 16px 24px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; gap: 12px; }
    .user-info { font-weight: 500; color: var(--text); display: flex; align-items: center; gap: 8px; }
    
    /* Cards */
    .card { background: var(--white); padding: 24px; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; overflow: hidden; }
    h3 { margin: 0; font-size: 18px; color: #111827; }
    h4 { margin: 24px 0 16px; font-size: 16px; color: #374151; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 8px; }
    .hint { font-size: 13px; color: var(--text-light); font-weight: normal; background: #f9fafb; padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border); }

    /* Forms */
    input, select { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; transition: border-color 0.2s, box-shadow 0.2s; background: #fff; }
    input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px; }
    .form-row { display: flex; align-items: center; gap: 8px; }
    label { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 14px; user-select: none; }
    input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--primary); margin: 0; }

    /* Buttons */
    button { height: 38px; padding: 0 16px; border: none; background: var(--primary); color: var(--white); border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; }
    button:hover { background: var(--primary-hover); }
    button:active { transform: translateY(1px); }
    .btn-secondary { background: #6b7280; }
    .btn-secondary:hover { background: #4b5563; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    .btn-success { background: var(--success); }
    .btn-success:hover { background: #059669; }
    .btn-sm { height: 32px; padding: 0 12px; font-size: 13px; }

    /* Actions Alignment */
    .actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .actions form { margin: 0; display: flex; }
    .actions input { height: 32px; padding: 0 10px; font-size: 13px; }
    
    /* Messages */
    .msg { background: #ecfdf5; color: #047857; padding: 12px 16px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #a7f3d0; display: flex; align-items: center; }

    /* Modal */
    .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; justify-content: center; align-items: center; z-index: 1000; }
    .modal { background: #fff; padding: 24px; border-radius: 12px; width: 90%; max-width: 400px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04); animation: modalIn 0.2s ease-out; }
    .modal-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; color: var(--text); }
    .modal-body { margin-bottom: 24px; color: #4b5563; font-size: 14px; line-height: 1.5; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 12px; }
    @keyframes modalIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
    
    /* Responsive Tables */
    table { width: 100%; border-collapse: separate; border-spacing: 0; }
    th { text-align: left; padding: 12px 16px; background: #f9fafb; font-weight: 600; font-size: 13px; color: var(--text-light); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
    td { padding: 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    
    /* Mobile styles */
    @media (max-width: 768px) {
      body { padding: 10px; padding-bottom: 80px; }
      .container { padding: 0; }
      .topbar { padding: 12px 16px; flex-direction: column; align-items: stretch; text-align: center; }
      .user-info { justify-content: center; margin-bottom: 8px; }
      .card { padding: 16px; border-radius: 12px; }
      
      /* Mobile Table -> Card View */
      table, thead, tbody, th, td, tr { display: block; }
      thead tr { position: absolute; top: -9999px; left: -9999px; }
      tr { margin-bottom: 16px; border: 1px solid var(--border); border-radius: 12px; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.05); overflow: hidden; }
      tr:last-child { margin-bottom: 0; }
      td { border: none; border-bottom: 1px solid #f3f4f6; position: relative; padding: 12px 16px; padding-left: 35%; display: flex; align-items: center; flex-wrap: wrap; min-height: 48px; }
      td:last-child { border-bottom: none; padding-left: 16px; justify-content: flex-end; background: #f9fafb; }
      
      /* Label for mobile */
      td::before { position: absolute; left: 16px; width: 30%; white-space: nowrap; font-weight: 600; font-size: 13px; color: var(--text-light); content: attr(data-label); }
      
      /* Inputs in table cells on mobile */
      td input, td select { width: 100%; }
      
      .form-grid { grid-template-columns: 1fr; }
      
      /* Hide "ID" inputs visually but keep them functional or use readonly style */
      input[readonly] { background: #f9fafb; color: #6b7280; border-color: transparent; padding-left: 0; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="user-info">
        <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
        SocksForward
      </div>
      <form method="post" action="/logout" style="margin:0"><button type="submit" class="btn-secondary btn-sm">退出登录</button></form>
    </div>
    
    {{if .Message}}
    <div class="msg">
      <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="margin-right: 8px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      {{.Message}}
    </div>
    {{end}}

    <div class="card">
      <div class="section-header">
        <h3>SOCKS5 节点</h3>
        <span class="hint">名称唯一，系统自动生成 ID</span>
      </div>
      
      {{if not .Nodes}}
      <div style="text-align:center; padding: 20px; color: var(--text-light);">暂无节点，请在下方添加</div>
      {{else}}
      <table>
        <thead>
          <tr>
            <th width="20%">名称</th>
            <th width="25%">地址</th>
            <th width="20%">用户名</th>
            <th width="20%">密码</th>
            <th width="15%">操作</th>
          </tr>
        </thead>
        <tbody>
          {{range .Nodes}}
          <tr>
            <form method="post" action="/nodes/update" style="margin:0">
              <td data-label="名称">
                <input type="hidden" name="id" value="{{.ID}}">
                <input name="name" value="{{.Name}}" required placeholder="名称">
              </td>
              <td data-label="地址"><input name="address" value="{{.Address}}" required placeholder="host:port"></td>
              <td data-label="用户名"><input name="username" value="{{.Username}}" placeholder="可选"></td>
              <td data-label="密码"><input name="password" type="password" value="{{.Password}}" placeholder="可选"></td>
              <td class="actions">
                <button type="submit" class="btn-sm" style="min-width: 60px">保存</button>
            </form>
                <form method="post" action="/nodes/delete" style="margin:0" onsubmit="confirmDelete(event, this)">
                  <input type="hidden" name="id" value="{{.ID}}">
                  <button type="submit" class="btn-danger btn-sm" style="min-width: 60px">删除</button>
                </form>
              </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{end}}

      <h4>新增节点</h4>
      <form method="post" action="/nodes/add">
        <div class="form-grid">
          <div><label class="small-label">名称</label><input name="name" placeholder="节点名称" required></div>
          <div><label class="small-label">地址</label><input name="address" placeholder="127.0.0.1:1080" required></div>
          <div><label class="small-label">用户名</label><input name="username" placeholder="可选"></div>
          <div><label class="small-label">密码</label><input name="password" type="password" placeholder="可选"></div>
        </div>
        <div class="form-row" style="justify-content: flex-end;">
           <button type="submit">添加节点</button>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="section-header">
        <h3>转发规则</h3>
        <span class="hint">名称唯一，必须选择出口节点</span>
      </div>

      {{if not .Rules}}
      <div style="text-align:center; padding: 20px; color: var(--text-light);">暂无规则，请在下方添加</div>
      {{else}}
      <table>
        <thead>
          <tr>
            <th width="15%">名称</th>
            <th width="10%">协议</th>
            <th width="20%">监听</th>
            <th width="20%">目标</th>
            <th width="15%">节点</th>
            <th width="20%">操作</th>
          </tr>
        </thead>
        <tbody>
          {{range .Rules}}
          {{$rule := .}}
          <tr>
            <form method="post" action="/rules/update" style="margin:0">
              <td data-label="名称">
                <input type="hidden" name="id" value="{{.ID}}">
                <input name="name" value="{{.Name}}" required placeholder="名称">
              </td>
              <td data-label="协议">
                <select name="proto">
                  <option value="tcp" {{if eq .Proto "tcp"}}selected{{end}}>TCP</option>
                  <option value="udp" {{if eq .Proto "udp"}}selected{{end}}>UDP</option>
                  <option value="both" {{if eq .Proto "both"}}selected{{end}}>Both</option>
                </select>
              </td>
              <td data-label="监听"><input name="listen" value="{{.Listen}}" required placeholder=":8080"></td>
              <td data-label="目标"><input name="target" value="{{.Target}}" required placeholder="host:port"></td>
              <td data-label="节点">
                <select name="socks5NodeId" required>
                  {{range $.Nodes}}
                  <option value="{{.ID}}" {{if eq .ID $rule.Socks5NodeID}}selected{{end}}>{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</option>
                  {{end}}
                </select>
              </td>
              <td class="actions">
                <button type="submit" class="btn-sm" style="min-width: 60px">保存</button>
            </form>
                <form method="post" action="/rules/toggle" style="margin:0">
                  <input type="hidden" name="id" value="{{.ID}}">
                  {{if .Enabled}}
                    {{if index $.RuleErrors .ID}}
                      <button type="submit" class="btn-sm btn-danger" style="min-width: 60px" title="{{index $.RuleErrors .ID}}">启动失败</button>
                    {{else}}
                      <button type="submit" class="btn-sm btn-success" style="min-width: 60px">已启用</button>
                    {{end}}
                  {{else}}
                    <button type="submit" class="btn-sm btn-secondary" style="min-width: 60px">已停用</button>
                  {{end}}
                </form>
                <form method="post" action="/rules/delete" style="margin:0" onsubmit="confirmDelete(event, this)">
                  <input type="hidden" name="id" value="{{.ID}}">
                  <button type="submit" class="btn-danger btn-sm" style="min-width: 60px">删除</button>
                </form>
              </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{end}}

      <h4>新增规则</h4>
      <form method="post" action="/rules/add">
        <div class="form-grid">
          <div><label class="small-label">名称</label><input name="name" placeholder="规则名称" required></div>
          <div>
            <label class="small-label">协议</label>
            <select name="proto" required>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">TCP & UDP</option>
            </select>
          </div>
          <div><label class="small-label">监听地址</label><input name="listen" placeholder=":8080" required></div>
          <div><label class="small-label">目标地址</label><input name="target" placeholder="1.1.1.1:443" required></div>
          <div>
            <label class="small-label">出口节点</label>
            <select name="socks5NodeId" required>
              {{range .Nodes}}<option value="{{.ID}}">{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</option>{{end}}
            </select>
          </div>
        </div>
        <div class="form-row" style="justify-content: space-between;">
          <label><input type="checkbox" name="enabled" checked> 立即启用</label>
          <button type="submit">添加规则</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h3>修改密码</h3>
      <form method="post" action="/password" style="margin-top: 16px;">
        <div class="form-grid">
          <div><input name="oldPassword" type="password" placeholder="当前密码" required autocomplete="current-password"></div>
          <div><input name="newPassword" type="password" placeholder="新密码" required autocomplete="new-password"></div>
        </div>
        <div class="form-row"><button type="submit">更新密码</button></div>
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
    
    // Close on outside click
    modal.onclick = function(e) {
      if (e.target === modal) closeModal();
    }
  </script>
</body>
</html>
`
