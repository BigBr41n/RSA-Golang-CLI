package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/urfave/cli/v2"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
)

// generateRSAKeys generates RSA private and public keys of specified bits.
func generateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// saveKeyToFile saves a key to a file.
func saveKeyToFile(filename string, keyBytes []byte) error {
	err := ioutil.WriteFile(filename, keyBytes, 0600)
	if err != nil {
		return err
	}
	fmt.Printf("Key saved to %s\n", filename)
	return nil
}

// loadKeyFromFile loads a key from a file.
func loadKeyFromFile(filename string) ([]byte, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// encryptRSA encrypts a message using RSA public key.
func encryptRSA(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// decryptRSA decrypts a message using RSA private key.
func decryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	message, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate RSA keys",
				Action: func(c *cli.Context) error {
					privateKey, publicKey, err := generateRSAKeys(2048)
					if err != nil {
						return err
					}
					privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
					publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
					if err != nil {
						return err
					}
					privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes})
					publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicBytes})
					if err := saveKeyToFile("private_key.pem", privateKeyPEM); err != nil {
						return err
					}
					if err := saveKeyToFile("public_key.pem", publicKeyPEM); err != nil {
						return err
					}
					return nil
				},
			},
			{
				Name:  "encrypt",
				Usage: "Encrypt a message",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}},
					&cli.StringFlag{Name: "message", Aliases: []string{"m"}},
				},
				Action: func(c *cli.Context) error {
					keyFile := c.String("key")
					message := c.String("message")

					keyBytes, err := loadKeyFromFile(keyFile)
					if err != nil {
						return err
					}
					block, _ := pem.Decode(keyBytes)
					if block == nil {
						return errors.New("failed to decode PEM block containing public key")
					}
					pub, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						return err
					}
					publicKey := pub.(*rsa.PublicKey)
					encrypted, err := encryptRSA(publicKey, []byte(message))
					if err != nil {
						return err
					}
					fmt.Printf("Encrypted message: %s\n", base64.StdEncoding.EncodeToString(encrypted))
					return nil
				},
			},
			{
				Name:  "decrypt",
				Usage: "Decrypt an encrypted message",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}},
					&cli.StringFlag{Name: "message", Aliases: []string{"m"}},
				},
				Action: func(c *cli.Context) error {
					keyFile := c.String("key")
					message := c.String("message")

					keyBytes, err := loadKeyFromFile(keyFile)
					if err != nil {
						return err
					}
					block, _ := pem.Decode(keyBytes)
					if block == nil {
						return errors.New("failed to decode PEM block containing private key")
					}
					priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
					if err != nil {
						return err
					}
					decrypted, err := base64.StdEncoding.DecodeString(message)
					if err != nil {
						return err
					}
					plaintext, err := decryptRSA(priv, decrypted)
					if err != nil {
						return err
					}
					fmt.Printf("Decrypted message: %s\n", plaintext)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

