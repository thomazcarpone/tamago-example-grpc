package network

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	bachelorpb "github.com/usbarmory/tamago-example/proto/bachelor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)	

var (
	//go:embed static/*
	static embed.FS // Système de fichiers embarqués pour les ressources statiques
	swaggerFilePath = "/static/bachelor/bachelor.swagger.json"
)

// Server implémente l'interface bachelorpb.GreeterServer
type server struct {
	bachelorpb.UnimplementedGreeterServer
}

// NewServer crée et retourne une nouvelle instance du serveur.
func NewServer() *server {
	return &server{}
}

// Fonction de générateur de nombre aléatoire qui utilise l'import crypto/rand
// et crée un vrai nombre aléatoire (TRNG)
func (s *server) RndGenerator(ctx context.Context, _ *bachelorpb.RndRequest) (*bachelorpb.RndReply, error) {
	buf := make([]byte, 32) // Génération tableau de bytes aléatoire
	rand.Read(buf)
	return &bachelorpb.RndReply{Message: fmt.Sprintf("%x", buf)}, nil // conversion tableau en hexadécimale
}

// Fonction pour la création d'un web serveur de base qui démarre le serveur web de base
// en fonction des paramètres spécifiés, ici la configuration s'effectue avec un serveur gRPC et la documentation OpenApi
func startWebServerBasic(listener net.Listener, addr string, port uint16, https bool) {
	var srv *http.Server
	var err error

	// Vérification si serveur démarre en https(TLS) ou http
	if https {
		srv, err = configureTLSServer(addr, port)
		if err != nil {
			log.Fatal("Failed to configure TLS server:", err)
		}
	} else {
		srv, err = configureHTTPServer(addr, port, listener)
		if err != nil {
			log.Fatal("Failed to configure HTTP server:", err)
		}
	}

	log.Println("Serving gRPC-Gateway on http://10.0.0.1:8090")
	// Lancement serveur gRPC-Gateway
	log.Fatalln(srv.ListenAndServe())

	log.Fatal("server returned unexpectedly ", err)
}


func configureHTTPServer(addr string, port uint16, listener net.Listener) (*http.Server, error) {
	// Création du serveur gRPC
	grpcServer := grpc.NewServer()
	bachelorpb.RegisterGreeterServer(grpcServer, &server{})
	log.Println("Serving gRPC on 10.0.0.1:8080")
	go func() {
		log.Fatalln(grpcServer.Serve(listener))
	}()

	// Etablissement d'une connexion gRPC vers le serveur
	conn, err := grpc.DialContext(
		context.Background(),
		"10.0.0.1:8080",
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial server: %v", err)
	}

	// Création d'un multiplexeur de requêtes HTTP. ServeMux peut gérer plusieurs routes
	gwmux := runtime.NewServeMux()
	muxSwagger := http.NewServeMux()
	configureSwaggerRoutes(muxSwagger)
	err = bachelorpb.RegisterGreeterHandler(context.Background(), gwmux, conn)
	if err != nil {
		return nil, fmt.Errorf("failed to register gateway: %v", err)
	}

	// Configuration des routes pour le serveur HTTP
	muxSwagger.Handle("/", gwmux)

	// Création du serveur HTTP avec les routes configurées
	srv := &http.Server{
		Addr:    ":8090",
		Handler: muxSwagger,
	}

	return srv, nil
}

// Fonction de configuration des routes Swagger pour le ServeMux HTTP
func configureSwaggerRoutes(muxSwagger *http.ServeMux) {
	// Création d'un gestionnaire de fichier car le système embarqué n'a pas son propre système de fichier
	// les fichiers sont stockés dans la variable static
	fileServer := http.FileServer(http.FS(static))
	muxSwagger.Handle("/bachelor/", http.StripPrefix("/bachelor/", fileServer))


	log.Printf("fileServer: %v\n", fileServer)

	// Vérification si le fichier de configuration Swagger existe dans la variable embarqué static
	if _, err := static.ReadFile("static/bachelor/bachelor.swagger.json"); err == nil {
		log.Println("Swagger configuration found")

		// Configuration des routes et des gestionnaires pour le serveur HTTP
		muxSwagger.HandleFunc(swaggerFilePath, func(w http.ResponseWriter, r *http.Request) {
			file, err := static.ReadFile("static/bachelor/bachelor.swagger.json")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Définition du type de contenu de la réponse HTTP comme JSON
			w.Header().Set("Content-Type", "application/json")
			w.Write(file)
		})
	}
}

// Fonction configure le serveur avec TLS et retourne le serveur configuré
func configureTLSServer(addr string, port uint16) (*http.Server, error) {
	// Génération des certificats TLS
	TLSCert, TLSKey, err := generateTLSCerts(net.ParseIP(addr))
	if err != nil {
		return nil, fmt.Errorf("TLS cert|key error: %v", err)
	}

	log.Printf("generated TLS certificate:\n%s", TLSCert)
	log.Printf("generated TLS key:\n%s", TLSKey)

	// Création de la paire de clés X.509 pour le certificat TLS
	certificate, err := tls.X509KeyPair(TLSCert, TLSKey)
	if err != nil {
		return nil, fmt.Errorf("X509KeyPair error: %v", err)
	}

	// Configuration du serveur HTTP avec prise en charge du TLS
	srv := &http.Server{
		Addr: addr + ":" + fmt.Sprintf("%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
	}

	return srv, nil
}