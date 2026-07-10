package main

import (
	"crypto/tls"
	"net"

	"github.com/clara/database-security-middleware/pkg/middleware"
)

func main() {
	middleware.LogMain.Println("Starting Database Security Middleware...")

	if err := middleware.InitKeys(); err != nil {
		middleware.LogMain.Fatalf("Erro ao inicializar chaves no Vault: %v", err)
	}

	backendHost := middleware.EnvOr("MIDDLEWARE_DB_HOST", "127.0.0.1")
	backendPort := middleware.EnvOr("MIDDLEWARE_DB_PORT", "5432")
	listenPort := middleware.EnvOr("MIDDLEWARE_LISTEN_PORT", "8000")

	listener, err := net.Listen("tcp", "0.0.0.0:"+listenPort)
	if err != nil {
		middleware.LogMain.Fatalf("Erro ao iniciar proxy na porta %s: %v", listenPort, err)
	}
	defer listener.Close()

	middleware.LogMain.Printf("Proxy escutando na porta %s e repassando para %s:%s", listenPort, backendHost, backendPort)

	cert, err := tls.LoadX509KeyPair("/certs/server.crt", "/certs/server.key")
	var tlsConfig *tls.Config
	if err != nil {
		middleware.LogMain.Printf("Aviso: Falha ao carregar certificados TLS: %v. TLS desabilitado", err)
	} else {
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		middleware.LogMain.Println("Certificados TLS carregados")
	}

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			middleware.LogMain.Println("Erro ao aceitar conexao:", err)
			continue
		}
		go middleware.HandleClient(clientConn, backendHost, backendPort, tlsConfig)
	}
}
