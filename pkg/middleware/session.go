package middleware

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
)

func HandleClient(client net.Conn, backendHost, backendPort string, tlsConfig *tls.Config) {
	defer client.Close()

	buf := make([]byte, 8)
	if _, err := io.ReadFull(client, buf); err != nil {
		LogSession.Println("Erro lendo header:", err)
		return
	}

	isSSLRequest :=
		buf[4] == 0x04 && buf[5] == 0xD2 &&
			buf[6] == 0x16 && buf[7] == 0x2F

	var finalClientConn net.Conn = client
	if isSSLRequest {
		if tlsConfig != nil {
			client.Write([]byte{'S'})
			finalClientConn = tls.Server(client, tlsConfig)
			LogSession.Println("Negociação TLS iniciada.")
		} else {
			client.Write([]byte{'N'})
		}
	}

	var startupMsg []byte

	if isSSLRequest {
		header := make([]byte, 4)
		if _, err := io.ReadFull(finalClientConn, header); err != nil {
			LogSession.Println("Erro ao ler header após SSLRequest:", err)
			return
		}
		sLen := int(binary.BigEndian.Uint32(header))
		if sLen < 8 || sLen > 10000 {
			return
		}
		body := make([]byte, sLen-4)
		if _, err := io.ReadFull(finalClientConn, body); err != nil {
			return
		}
		startupMsg = append(header, body...)
	} else {
		sLen := int(binary.BigEndian.Uint32(buf[:4]))
		if sLen < 8 || sLen > 10000 {
			return
		}
		if sLen > 8 {
			remaining := make([]byte, sLen-8)
			if _, err := io.ReadFull(finalClientConn, remaining); err != nil {
				return
			}
			startupMsg = append(buf, remaining...)
		} else {
			startupMsg = make([]byte, len(buf))
			copy(startupMsg, buf)
		}
	}

	params := ParseStartupParams(startupMsg)
	database := params["database"]
	LogSession.Printf("Conexao: user='%s' database='%s'", params["user"], database)

	dbConn, err := net.Dial("tcp", backendHost+":"+backendPort)
	if err != nil {
		LogSession.Printf("Erro conectando ao backend: %v", err)
		return
	}
	defer dbConn.Close()

	var finalDbConn net.Conn = dbConn

	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	if _, err := dbConn.Write(sslReq); err == nil {
		resp := make([]byte, 1)
		if _, err := io.ReadFull(dbConn, resp); err == nil {
			if resp[0] == 'S' {
				tlsConfig := &tls.Config{InsecureSkipVerify: true}
				finalDbConn = tls.Client(dbConn, tlsConfig)
				LogSession.Println("[Backend] Conexão TLS estabelecida com o banco de dados.")
			} else if resp[0] == 'N' {
				LogSession.Println("[Backend] Banco de dados não suporta TLS. Seguindo em texto claro.")
			}
		}
	}

	// Envia a mensagem de Startup no túnel (seguro ou cru)
	if _, err := finalDbConn.Write(startupMsg); err != nil {
		LogSession.Printf("Erro enviando startupMsg ao backend: %v", err)
		return
	}

	readyPayload, err := relayAuth(finalClientConn, finalDbConn)
	if err != nil {
		LogSession.Printf("Erro autenticação: %v", err)
		return
	}

	if err := loadAllMetadata(finalDbConn, database); err != nil {
		LogSession.Printf("Aviso: %v (proxy sem criptografia)", err)
	}

	writeWireMessage(finalClientConn, 'Z', readyPayload)

	LogSession.Println("Proxy iniciado")

	session := &Session{
		clientConn: finalClientConn,
		dbConn:     finalDbConn,
		parser: &PgParser{
			statements: make(map[string]StatementMetaData),
			database:   database,
		},
	}

	done := make(chan struct{}, 1)

	go func() {
		session.proxyDBToClient()
		done <- struct{}{}
	}()

	session.proxyClientToDB()

	<-done
}

func relayAuth(clientConn, dbConn net.Conn) ([]byte, error) {
	for {
		msgType, payload, err := readWireMessage(dbConn)
		if err != nil {
			return nil, fmt.Errorf("Lendo do DB: %w", err)
		}

		switch msgType {
		case 'R':
			writeWireMessage(clientConn, msgType, payload)

			if len(payload) >= 4 {
				authType := binary.BigEndian.Uint32(payload[:4])

				if authType == 3 || authType == 5 ||
					authType == 10 || authType == 11 {
					ct, cp, err := readWireMessage(clientConn)
					if err != nil {
						return nil, fmt.Errorf("Lendo auth do cliente: %w", err)
					}
					writeWireMessage(dbConn, ct, cp)
				}
			}

		case 'Z':
			return payload, nil

		case 'E':
			writeWireMessage(clientConn, msgType, payload)
			return nil, fmt.Errorf("Erro de autenticao do DB")

		default:

			writeWireMessage(clientConn, msgType, payload)
		}
	}
}

func (s *Session) proxyClientToDB() {
	for {
		msgType, payload, err := readWireMessage(s.clientConn)
		if err != nil {
			return
		}

		newPayload, filterCtx := s.parser.ProcessMessage(msgType, payload)

		if filterCtx.ColName != "" {
			s.filterColName = filterCtx.ColName
			s.filterValue = filterCtx.Value
		}
		if err := writeWireMessage(s.dbConn, msgType, newPayload); err != nil {
			return
		}
	}
}

func (s *Session) proxyDBToClient() {
	for {
		msgType, payload, err := readWireMessage(s.dbConn)
		if err != nil {
			return
		}

		if msgType == 'T' {
			s.parseRowDescription(payload)
			if err := writeWireMessage(s.clientConn, msgType, payload); err != nil {
				return
			}
			continue
		}

		if s.intercepting {
			if msgType == 'D' {
				vals := parseDataRowBytes(payload)
				modified := false

				var cachedWrappedDek string
				var cachedDek []byte

				for _, target := range s.decryptTargets {
					if target.ColIndex < len(vals) {
						val := vals[target.ColIndex]
						if len(val) > 0 {
							encHex := string(val)
							encBytes, err := hex.DecodeString(encHex)
							if err == nil {
								var dek []byte
								var errDek error
								var dataBytes []byte

								if len(encBytes) >= 256+12+16 {
									wrappedDek := encBytes[:256]
									dataBytes = encBytes[256:]

									if string(wrappedDek) == cachedWrappedDek {
										dek = cachedDek
									} else {
										dek, errDek = unwrapDEK(wrappedDek, masterPrivateKey)
										if errDek == nil {
											cachedWrappedDek = string(wrappedDek)
											cachedDek = dek
										}
									}
								} else if len(encBytes) >= 12+16 {
									dek = SharedDEK
									dataBytes = encBytes
								}

								if errDek == nil && len(dek) == 32 {
									dekBlock, _ := aes.NewCipher(dek)
									dekGcm, _ := cipher.NewGCM(dekBlock)
									dekNonce, dataCipher := dataBytes[:12], dataBytes[12:]
									plaintext, errData := dekGcm.Open(nil, dekNonce, dataCipher, nil)

									if errData == nil {
										vals[target.ColIndex] = plaintext
										modified = true
									}
								}
							}
						}
					}
				}

				if s.filterColIndex >= 0 && s.filterColIndex < len(vals) && s.filterValue != "" {
					plaintextVal := string(vals[s.filterColIndex])
					if !strings.Contains(strings.ToLower(plaintextVal), strings.ToLower(s.filterValue)) {
						continue
					}
				}

				s.rowsSent++
				newPayload := payload
				if modified {
					newPayload = buildDataRow(vals)
				}
				if err := writeWireMessage(s.clientConn, 'D', newPayload); err != nil {
					return
				}
				continue
			} else if msgType == 'C' {
				if s.filterColIndex >= 0 {
					cmdStr := string(payload)
					parts := strings.Split(cmdStr, " ")
					if len(parts) > 1 {
						parts[len(parts)-1] = fmt.Sprintf("%d\x00", s.rowsSent)
						newCmd := strings.Join(parts, " ")
						payload = []byte(newCmd)
					}
				}
				s.intercepting = false
			} else if msgType == 'Z' || msgType == 'E' {
				s.intercepting = false
			}
		}

		if err := writeWireMessage(s.clientConn, msgType, payload); err != nil {
			return
		}
	}
}

func (s *Session) parseRowDescription(payload []byte) {
	s.intercepting = false
	s.decryptTargets = nil
	s.filterColIndex = -1

	pos := 0
	if pos+2 > len(payload) {
		return
	}
	numCols := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	for i := 0; i < numCols; i++ {
		end := bytes.IndexByte(payload[pos:], 0)
		if end < 0 {
			break
		}
		colName := string(payload[pos : pos+end])
		pos += end + 1

		if pos+18 > len(payload) {
			break
		}
		tableOID := int32(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 18

		if s.filterColName != "" && strings.EqualFold(colName, s.filterColName) {
			s.filterColIndex = i
		}

		if tableName, ok := s.parser.getTableNameFromOID(tableOID); ok {
			tableMeta, hasMeta := s.parser.getTableMeta(tableName)
			if hasMeta {
				if sec, colExists := tableMeta.Columns[colName]; colExists && sec.Encrypt {
					s.intercepting = true
					s.decryptTargets = append(s.decryptTargets, DecryptTarget{
						ColIndex:  i,
						TableName: tableName,
					})
				}
			}
		}
	}
}
