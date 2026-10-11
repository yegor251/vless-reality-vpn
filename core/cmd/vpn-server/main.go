package main

import (
	"flag"
	"log"
	"net"
	"time"

	"vpn/internal/auth"
	"vpn/internal/config"
	"vpn/internal/proxy"
	"vpn/internal/reality"
)

func main() {
	configPath := flag.String("config", "server.json", "path to server config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	users, err := auth.NewStore(cfg.Users)
	if err != nil {
		log.Fatalf("init users: %v", err)
	}

	var rcfg *reality.Config
	if cfg.Reality != nil {
		rcfg, err = reality.NewConfig(
			cfg.Reality.Dest,
			cfg.Reality.ServerNames,
			cfg.Reality.PrivateKey,
			cfg.Reality.ShortIds,
			time.Duration(cfg.Reality.MaxTimeDiffSec)*time.Second,
		)
		if err != nil {
			log.Fatalf("init reality: %v", err)
		}
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	if rcfg != nil {
		log.Printf("vpn-server listening on %s, %d user(s), reality dest %s",
			cfg.Listen, len(cfg.Users), rcfg.Dest)
	} else {
		log.Printf("vpn-server listening on %s, %d user(s)", cfg.Listen, len(cfg.Users))
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go proxy.Handle(conn, users, rcfg)
	}
}
