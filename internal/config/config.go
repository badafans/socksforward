package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
)

type Config struct {
	Web     WebConfig     `json:"web"`
	Socks5  Socks5Config  `json:"socks5"`
	Forward ForwardConfig `json:"forward"`
}

type WebConfig struct {
	PasswordSaltB64   string `json:"passwordSaltB64"`
	PasswordSha256B64 string `json:"passwordSha256B64"`
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
		Web: WebConfig{},
		Socks5: Socks5Config{
			Nodes: []Socks5Node{},
		},
		Forward: ForwardConfig{
			Rules: []ForwardRule{},
		},
	}
}

func Load(path string, defaultPassword string) (*Config, error) {
	if defaultPassword == "" {
		return nil, errors.New("默认密码不能为空")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		cfg := DefaultConfig()
		changed, err := ensureDefaultWeb(cfg, defaultPassword)
		if err != nil {
			return nil, err
		}
		if changed {
			if err := Save(path, cfg); err != nil {
				return nil, err
			}
		}
		return cfg, nil
	}

	if len(b) == 0 {
		cfg := DefaultConfig()
		changed, err := ensureDefaultWeb(cfg, defaultPassword)
		if err != nil {
			return nil, err
		}
		if changed {
			if err := Save(path, cfg); err != nil {
				return nil, err
			}
		}
		return cfg, nil
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}

	changed, err := ensureDefaultWeb(cfg, defaultPassword)
	if err != nil {
		return nil, err
	}
	if changed {
		if err := Save(path, cfg); err != nil {
			return nil, err
		}
	}

	if cfg.Socks5.Nodes == nil {
		cfg.Socks5.Nodes = []Socks5Node{}
	}
	if cfg.Forward.Rules == nil {
		cfg.Forward.Rules = []ForwardRule{}
	}
	return cfg, nil
}

func Save(path string, cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func Clone(cfg *Config) *Config {
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

func VerifyPassword(cfg *Config, password string) bool {
	if cfg == nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(cfg.Web.PasswordSaltB64)
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(cfg.Web.PasswordSha256B64)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(append(salt, []byte(password)...))
	return subtle.ConstantTimeCompare(sum[:], expected) == 1
}

func UpdatePassword(cfg *Config, newPassword string) error {
	if cfg == nil {
		return errors.New("配置为空")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	sum := sha256.Sum256(append(salt, []byte(newPassword)...))
	cfg.Web.PasswordSaltB64 = base64.StdEncoding.EncodeToString(salt)
	cfg.Web.PasswordSha256B64 = base64.StdEncoding.EncodeToString(sum[:])
	return nil
}

func ensureDefaultWeb(cfg *Config, defaultPassword string) (bool, error) {
	if cfg.Web.PasswordSaltB64 != "" && cfg.Web.PasswordSha256B64 != "" {
		return false, nil
	}
	if err := UpdatePassword(cfg, defaultPassword); err != nil {
		return false, err
	}
	return true, nil
}
