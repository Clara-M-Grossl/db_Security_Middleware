package middleware

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

func readWireMessage(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}

	msgType := header[0]
	length := int(binary.BigEndian.Uint32(header[1:5]))

	if length <= 4 {
		return msgType, nil, nil
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}

	return msgType, payload, nil
}

func writeWireMessage(conn net.Conn, msgType byte, payload []byte) error {
	length := uint32(len(payload) + 4)
	buf := make([]byte, 1+4+len(payload))
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], length)
	copy(buf[5:], payload)
	_, err := conn.Write(buf)
	return err
}

func sendSimpleQuery(conn net.Conn, query string) error {
	payload := append([]byte(query), 0)
	return writeWireMessage(conn, 'Q', payload)
}

func parseDataRow(payload []byte) []string {
	if len(payload) < 2 {
		return nil
	}
	numCols := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2
	values := make([]string, 0, numCols)

	for i := 0; i < numCols; i++ {
		if pos+4 > len(payload) {
			break
		}
		colLen := int(int32(binary.BigEndian.Uint32(payload[pos:])))
		pos += 4
		if colLen == -1 {
			values = append(values, "")
			continue
		}
		if pos+colLen > len(payload) {
			break
		}
		values = append(values, string(payload[pos:pos+colLen]))
		pos += colLen
	}
	return values
}

func parseDataRowBytes(payload []byte) [][]byte {
	if len(payload) < 2 {
		return nil
	}
	numCols := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2
	values := make([][]byte, 0, numCols)

	for i := 0; i < numCols; i++ {
		if pos+4 > len(payload) {
			break
		}
		colLen := int(int32(binary.BigEndian.Uint32(payload[pos:])))
		pos += 4
		if colLen == -1 {
			values = append(values, nil)
			continue
		}
		if pos+colLen > len(payload) {
			break
		}
		values = append(values, payload[pos:pos+colLen])
		pos += colLen
	}
	return values
}

func buildDataRow(values [][]byte) []byte {
	var buf bytes.Buffer
	numCols := uint16(len(values))
	binary.Write(&buf, binary.BigEndian, numCols)

	for _, val := range values {
		if val == nil {
			binary.Write(&buf, binary.BigEndian, int32(-1))
		} else {
			binary.Write(&buf, binary.BigEndian, int32(len(val)))
			buf.Write(val)
		}
	}
	return buf.Bytes()
}

func ParseStartupParams(msg []byte) map[string]string {
	params := make(map[string]string)
	if len(msg) < 9 {
		return params
	}
	data := msg[8:]
	pos := 0
	for pos < len(data) {
		keyEnd := bytes.IndexByte(data[pos:], 0)
		if keyEnd <= 0 {
			break
		}
		key := string(data[pos : pos+keyEnd])
		pos += keyEnd + 1
		valEnd := bytes.IndexByte(data[pos:], 0)
		if valEnd < 0 {
			break
		}
		value := string(data[pos : pos+valEnd])
		pos += valEnd + 1
		params[key] = value
	}
	return params
}
