package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Printf("Erro ao gerar chave privada: %v\n", err)
		return
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DoBotShield"},
			Country:      []string{"BR"},
			Province:     []string{"PB"},
			Locality:     []string{"RioTinto"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Printf("Erro ao criar certificado: %v\n", err)
		return
	}

	certOut, err := os.Create("server.crt")
	if err != nil {
		fmt.Printf("Erro ao criar server.crt: %v\n", err)
		return
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	fmt.Println("server.crt gerado.")

	keyOut, err := os.Create("server.key")
	if err != nil {
		fmt.Printf("Erro ao criar server.key: %v\n", err)
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	fmt.Println("server.key gerado.")
}
