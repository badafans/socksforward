package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"socksforward/internal/config"
	"socksforward/internal/forward"
	"socksforward/internal/web"
)

func main() {
	webPort := flag.Int("port", 8080, "Web 管理端口")
	configPath := flag.String("config", "config.json", "配置文件路径")
	defaultPassword := flag.String("password", "123456", "默认 Web 管理密码 (仅在首次初始化配置时生效)")
	flag.Parse()

	if *defaultPassword == "" {
		log.Fatal("默认密码不能为空")
	}

	cfg, err := config.Load(*configPath, *defaultPassword)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	manager := forward.NewManager()
	manager.Apply(cfg)

	server := web.NewServer(cfg, *configPath, manager)
	addr := fmt.Sprintf("0.0.0.0:%d", *webPort)
	log.Printf("Web 管理监听: %s", addr)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatalf("Web 服务启动失败: %v", err)
	}
}
