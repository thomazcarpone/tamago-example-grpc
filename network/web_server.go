// https://github.com/usbarmory/tamago-example
//
// Copyright (c) WithSecure Corporation
// https://foundry.withsecure.com
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package network

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"fmt"
	"html"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	bachelorpb "github.com/usbarmory/tamago-example/proto/bachelor"
)

//go:embed static/*
var static embed.FS

const (
	pathSwaggerJson = "swagger/swagger-ui/example/hello_world.swagger.json" // chemin fichier JSON Swagger
)

func flushingHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "Fri, 07 Jan 1981 00:00:00 GMT")

		journal.Sync()

		h.ServeHTTP(w, r)
	}
}

func applyHeaders(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "Fri, 07 Jan 1981 00:00:00 GMT")

		journal.Sync()

		h.ServeHTTP(w, r)
	}
}

func SetupStaticWebAssetsSwagger(banner string) {
	root, err := fs.Sub(static, "static")

	if err != nil {
		return
	}

	static := http.FileServer(http.FS(root))
	staticHandler := applyHeaders(static)

	http.Handle("/", http.StripPrefix("/", staticHandler))
	http.HandleFunc("/api/", apiHandler)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.RequestURI {
	default:
		handleRequest(w, r)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	var res *bachelorpb.RndReply

	switch r.RequestURI {
	case "/api/v1/example/rndGen":
		// Create an instance of the server struct
		s := &server{}

		// Call the RndGenerator method on the server instance
		reply, err := s.RndGenerator(context.Background(), &bachelorpb.RndRequest{})
		if err != nil {
			// Handle the error if needed
			log.Println("Error calling RndGenerator:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Assign the result to the res variable
		res = reply
	}

	if res != nil {
		sendResponse(w, res)
	}
}

func sendResponse(w http.ResponseWriter, res *bachelorpb.RndReply) {
	fmt.Fprint(w, res.String())
}

func SetupStaticWebAssets(banner string) {
	file, err := os.OpenFile("/index.html", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		panic(err)
	}
	defer file.Close()

	file.WriteString("<html><body>")
	file.WriteString(fmt.Sprintf("<p>%s</p><ul>", html.EscapeString(banner)))
	file.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a></li>`, "/tamago-example.log", "/tamago-example.log"))
	file.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a></li>`, "/dir", "/dir"))
	file.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a></li>`, "/debug/pprof", "/debug/pprof"))
	file.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a></li>`, "/debug/statsviz", "/debug/statsviz"))
	file.WriteString("</ul></body></html>")

	static := http.FileServer(http.Dir("/"))
	staticHandler := flushingHandler(static)
	http.Handle("/", http.StripPrefix("/", staticHandler))
}

func startWebServerBasic(listener net.Listener, addr string, port uint16, https bool) {
	var err error
	var srv http.Server
	
	if https {
		srv := &http.Server{
			Addr: addr + ":" + fmt.Sprintf("%d", port),
		}

		TLSCert, TLSKey, err := generateTLSCerts(net.ParseIP(addr))

		if err != nil {
			log.Fatal("TLS cert|key error: ", err)
		}

		log.Printf("generated TLS certificate:\n%s", TLSCert)
		log.Printf("generated TLS key:\n%s", TLSKey)

		certificate, err := tls.X509KeyPair(TLSCert, TLSKey)

		if err != nil {
			log.Fatal("X509KeyPair error: ", err)
		}

		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
		}
	}

	log.Printf("starting web server at %s:%d", addr, port)

	if https {
		err = srv.ServeTLS(listener, "", "")
	} else {
		s := grpc.NewServer()
		bachelorpb.RegisterGreeterServer(s, &server{})
		log.Println("Serving gRPC on 10.0.0.1:8080")
		go func() {
			log.Fatalln(s.Serve(listener))
		}()

		conn, err := grpc.DialContext(
			context.Background(),
			"10.0.0.1:8080",
			grpc.WithBlock(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			log.Fatalln("Failed to dial server:", err)
		}

		// Création de la passerelle gRPC
		gwmux := runtime.NewServeMux()
		// Implémentation de la gestion des requêtes liées à Swagger
		muxSwagger := http.NewServeMux()
		muxSwagger.Handle("/", gwmux) //routes par défaut gérées par le gwmux
		 
		// Enregistrement du service 'Greeter' avec gwmux
		err = bachelorpb.RegisterGreeterHandler(context.Background(), gwmux, conn)
		

		// Activation de swagger si on trouve le swagger.json
		if _, err := os.Stat("swagger/swagger-ui/example/hello_world.swagger.json"); err == nil {
			log.Println("Swagger configuration found")
			muxSwagger.HandleFunc("swagger/swagger-ui/example/swagger.json", func(w http.ResponseWriter, r *http.Request){
				// Indique au serveur de renvoyer le contenu du swagger.json quand le fichier est appelé
				http.ServeFile(w, r, pathSwaggerJson)
			})

			// Indique racine swagger-ui
			fs := http.FileServer(http.Dir("swagger/swagger-ui"))
			// Appel l'url "swagger-ui", affichage du contenu du dossier
			muxSwagger.Handle("/swagger-ui/", http.StripPrefix("/swagger-ui/", fs))
		}
				
		if err != nil {
			log.Fatalln("Failed to register gateway:", err)
		}

		gwServer := &http.Server{
			Addr:    ":8090",
			Handler: gwmux,
		}

		log.Println("Serving gRPC-Gateway on http://10.0.0.1:8090")
		// Lancement serveur gRPC-Gateway
		log.Fatalln(gwServer.ListenAndServe())
		}

		log.Fatal("server returned unexpectedly ", err)
}

type server struct{
	bachelorpb.UnimplementedGreeterServer
}

func NewServer() *server {
	return &server{}
}

func (s *server) RndGenerator(ctx context.Context, _ *bachelorpb.RndRequest) (*bachelorpb.RndReply, error) {
	// Génération tableau de bytes aléatoire
	buf := make([]byte, 32)
	rand.Read(buf)
    
	return &bachelorpb.RndReply{Message: fmt.Sprintf("%x", buf)}, nil // conversion tablean en hexadécimale
}

func startWebServer(listener net.Listener, addr string, port uint16, https bool) {
	var err error

	srv := &http.Server{
		Addr: addr + ":" + fmt.Sprintf("%d", port),
	}

	if https {
		TLSCert, TLSKey, err := generateTLSCerts(net.ParseIP(addr))

		if err != nil {
			log.Fatal("TLS cert|key error: ", err)
		}

		log.Printf("generated TLS certificate:\n%s", TLSCert)
		log.Printf("generated TLS key:\n%s", TLSKey)

		certificate, err := tls.X509KeyPair(TLSCert, TLSKey)

		if err != nil {
			log.Fatal("X509KeyPair error: ", err)
		}

		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
		}
	}

	log.Printf("starting web server at %s:%d", addr, port)

	if https {
		err = srv.ServeTLS(listener, "", "")
	} else {
		err = srv.Serve(listener)
	}

	log.Fatal("server returned unexpectedly ", err)
}

func generateTLSCerts(address net.IP) ([]byte, []byte, error) {
	TLSCert := new(bytes.Buffer)
	TLSKey := new(bytes.Buffer)

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))

	log.Printf("generating TLS keypair IP: %s, Serial: %X", address.String(), serial)

	validFrom, _ := time.Parse(time.RFC3339, "1981-01-07T00:00:00Z")
	validUntil, _ := time.Parse(time.RFC3339, "2022-01-07T00:00:00Z")

	certTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"TamaGo Example"},
			OrganizationalUnit: []string{"TamaGo test certificates"},
			CommonName:         address.String(),
		},
		IPAddresses:        []net.IP{address},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          validFrom,
		NotAfter:           validUntil,
		SubjectKeyId:       []byte{1, 2, 3, 4, 5},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	caTemplate := certTemplate
	caTemplate.SerialNumber = serial
	caTemplate.SubjectKeyId = []byte{1, 2, 3, 4, 6}
	caTemplate.BasicConstraintsValid = true
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	caTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &caTemplate, pub, priv)

	if err != nil {
		return nil, nil, err
	}

	pem.Encode(TLSCert, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	ecb, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(TLSKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	h := sha256.New()
	h.Write(cert)

	log.Printf("SHA-256 fingerprint: % X", h.Sum(nil))

	return TLSCert.Bytes(), TLSKey.Bytes(), nil
}
