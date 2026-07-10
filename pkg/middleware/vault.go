package middleware

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"io"
	"net/http"
	"os"
	"time"
)

var vaultAddr = EnvOr("VAULT_ADDR", "http://127.0.0.1:8200")
var vaultToken = EnvOr("VAULT_TOKEN", "root")

func init() {
	initFile := "/vault/file/init.json"
	if _, err := os.Stat(initFile); err == nil {
		file, err := os.Open(initFile)
		if err == nil {
			defer file.Close()
			var data struct {
				RootToken string `json:"root_token"`
			}
			if err := json.NewDecoder(file).Decode(&data); err == nil && data.RootToken != "" {
				vaultToken = data.RootToken
			}
		}
	}
}

func fetchOrGenerateKey(secretPath, keyName string) ([]byte, error) {
	client := &http.Client{}

	var resp *http.Response
	var err error

	for i := 0; i < 5; i++ {
		req, errReq := http.NewRequest("GET", vaultAddr+secretPath, nil)
		if errReq != nil {
			return nil, errReq
		}
		req.Header.Set("X-Vault-Token", vaultToken)

		resp, err = client.Do(req)
		if err == nil {
			break 
		}
		LogVault.Printf("Tentativa %d/5: Erro conectando ao Vault: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		LogVault.Printf("5 tentativas")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			Data struct {
				Data struct {
					Key string `json:"key"`
				} `json:"data"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if len(result.Data.Data.Key) > 0 {
				LogVault.Printf("Chave '%s' recuperada", keyName)
				keyBytes := []byte(result.Data.Data.Key)
				if len(keyBytes) >= 32 {
					return keyBytes[:32], nil
				}
			}
		}
	}

	LogVault.Printf("Chave '%s' nao encontrada. Gerando nova chave e salvando no Vault...", keyName)

	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"data": map[string]string{
			"key": string(newKey),
		},
	}
	body, _ := json.Marshal(payload)

	reqPost, err := http.NewRequest("POST", vaultAddr+secretPath, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	reqPost.Header.Set("X-Vault-Token", vaultToken)
	reqPost.Header.Set("Content-Type", "application/json")

	respPost, err := client.Do(reqPost)
	if err != nil {
		LogVault.Printf("Erro ao salvar chave no Vault: %v", err)
		return nil, err
	}
	defer respPost.Body.Close()

	if respPost.StatusCode >= 200 && respPost.StatusCode < 300 {
		LogVault.Printf("Nova chave '%s' armazenada", keyName)
	} else {
		b, _ := io.ReadAll(respPost.Body)
		LogVault.Printf("Aviso: Falha ao salvar chave '%s' no Vault (Status %d): %s", keyName, respPost.StatusCode, string(b))
	}

	return newKey, nil
}

func fetchOrGenerateRSAKey(secretPath, keyName string) (*rsa.PrivateKey, error) {
	client := &http.Client{}

	var resp *http.Response
	var err error

	for i := 0; i < 5; i++ {
		req, errReq := http.NewRequest("GET", vaultAddr+secretPath, nil)
		if errReq != nil {
			return nil, errReq
		}
		req.Header.Set("X-Vault-Token", vaultToken)

		resp, err = client.Do(req)
		if err == nil {
			break
		}
		LogVault.Printf("Tentativa %d/5: Erro conectando ao Vault para RSA: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		LogVault.Printf("5 tentativas")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			Data struct {
				Data struct {
					PrivateKey string `json:"private_key"`
				} `json:"data"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if len(result.Data.Data.PrivateKey) > 0 {
				LogVault.Printf("Chave RSA '%s' recuperada", keyName)
				block, _ := pem.Decode([]byte(result.Data.Data.PrivateKey))
				if block != nil {
					priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
					if err == nil {
						return priv, nil
					}
				}
			}
		}
	}

	LogVault.Printf("Chave RSA '%s' nao encontrada. Gerando nova chave RSA...", keyName)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})

	payload := map[string]interface{}{
		"data": map[string]string{
			"private_key": string(privPEM),
		},
	}
	body, _ := json.Marshal(payload)

	reqPost, err := http.NewRequest("POST", vaultAddr+secretPath, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	reqPost.Header.Set("X-Vault-Token", vaultToken)
	reqPost.Header.Set("Content-Type", "application/json")

	respPost, err := client.Do(reqPost)
	if err == nil {
		defer respPost.Body.Close()
		if respPost.StatusCode >= 200 && respPost.StatusCode < 300 {
			LogVault.Printf("Nova chave RSA '%s' armazenada", keyName)
		} else {
			b, _ := io.ReadAll(respPost.Body)
			LogVault.Printf("Aviso: Falha ao salvar RSA '%s' (Status %d): %s", keyName, respPost.StatusCode, string(b))
		}
	}

	return privateKey, nil
}

func InitKeys() error {
	var err error
	
	EncryptionMode = EnvOr("MIDDLEWARE_ENCRYPTION_MODE", "per_row")
	LogVault.Printf("Modo de Criptografia configurado para: %s", EncryptionMode)

	masterPrivateKey, err = fetchOrGenerateRSAKey("/v1/secret/data/middleware/master_rsa", "master_rsa")
	if err != nil {
		return err
	}

	blindIndexKey, err = fetchOrGenerateKey("/v1/secret/data/middleware/blind_index_key", "blind_index_key")
	if err != nil {
		return err
	}

	SharedDEK, err = fetchOrGenerateKey("/v1/secret/data/middleware/shared_dek", "shared_dek")
	if err != nil {
		return err
	}

	return nil
}
