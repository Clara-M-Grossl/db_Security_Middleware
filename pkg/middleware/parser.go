package middleware

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func (p *PgParser) ProcessMessage(msgType byte, payload []byte) ([]byte, FilterContext) {
	switch msgType {
	case 'P':
		return p.parseParse(payload), FilterContext{}
	case 'B':
		return p.parseBind(payload)
	default:
		return payload, FilterContext{}
	}
}

func (p *PgParser) parseParse(payload []byte) []byte {
	pos := 0

	stmtEnd := bytes.IndexByte(payload[pos:], 0)
	if stmtEnd < 0 {
		return payload
	}
	stmtName := string(payload[pos : pos+stmtEnd])
	pos += stmtEnd + 1

	queryEnd := bytes.IndexByte(payload[pos:], 0)
	if queryEnd < 0 {
		return payload
	}
	query := string(payload[pos : pos+queryEnd])

	numParamsPos := pos + queryEnd + 1
	if numParamsPos+2 > len(payload) {
		return payload
	}
	numParams := int(binary.BigEndian.Uint16(payload[numParamsPos : numParamsPos+2]))

	tree, err := pg_query.Parse(query)
	if err != nil || len(tree.Stmts) == 0 {
		return payload
	}

	if insertStmt := tree.Stmts[0].Stmt.GetInsertStmt(); insertStmt != nil {
		table := insertStmt.Relation.Relname
		tableMeta, ok := p.getTableMeta(table)
		if !ok {
			return payload
		}

		columns := make([]string, 0)
		blindIndexes := make([]BlindIndexGen, 0)
		addedBlindIndexes := make([]string, 0)

		for i, item := range insertStmt.Cols {
			target := item.GetResTarget()
			if target != nil {
				colName := strings.ToLower(target.Name)
				columns = append(columns, colName)

				if sec, exists := tableMeta.Columns[colName]; exists && sec.BlindIndex != "" {
					addedBlindIndexes = append(addedBlindIndexes, sec.BlindIndex)
					blindIndexes = append(blindIndexes, BlindIndexGen{SourceIndex: i})
				}
			}
		}

		p.statements[stmtName] = StatementMetaData{
			Table:              table,
			Columns:            columns,
			InsertBlindIndexes: blindIndexes,
		}

		if len(addedBlindIndexes) == 0 {
			LogParser.Printf("INSERT em '%s', sem blind indexes", table)
			return payload
		}

		selectStmt := insertStmt.SelectStmt.GetSelectStmt()
		if selectStmt == nil || len(selectStmt.ValuesLists) == 0 {
			return payload
		}
		valuesList := selectStmt.ValuesLists[0].GetList()

		for _, targetCol := range addedBlindIndexes {
			insertStmt.Cols = append(insertStmt.Cols, &pg_query.Node{
				Node: &pg_query.Node_ResTarget{
					ResTarget: &pg_query.ResTarget{
						Name: targetCol,
					},
				},
			})

			valuesList.Items = append(valuesList.Items, &pg_query.Node{
				Node: &pg_query.Node_ParamRef{
					ParamRef: &pg_query.ParamRef{
						Number:   int32(len(valuesList.Items) + 1),
						Location: -1,
					},
				},
			})
		}

		newQuery, err := pg_query.Deparse(tree)
		if err != nil {
			LogParser.Printf("Erro no deparse: %v", err)
			return payload
		}

		LogParser.Printf("Query reescrita para Blind Index: %s", newQuery)

		newPayload := make([]byte, 0, len(payload)+len(newQuery)-len(query)+len(addedBlindIndexes)*4)
		newPayload = append(newPayload, []byte(stmtName)...)
		newPayload = append(newPayload, 0)
		newPayload = append(newPayload, []byte(newQuery)...)
		newPayload = append(newPayload, 0)

		newNumParams := numParams + len(addedBlindIndexes)
		npBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(npBytes, uint16(newNumParams))
		newPayload = append(newPayload, npBytes...)

		oldParamOIDsSize := numParams * 4
		newPayload = append(newPayload, payload[numParamsPos+2:numParamsPos+2+oldParamOIDsSize]...)

		for i := 0; i < len(addedBlindIndexes); i++ {
			newPayload = append(newPayload, 0, 0, 0, 0)
		}

		return newPayload
	}

	if selectStmt := tree.Stmts[0].Stmt.GetSelectStmt(); selectStmt != nil {
		selectParamMap := make(map[int]string)

		var filterColName string
		var filterParamIndex int = -1

		cacheMu.RLock()
		for _, meta := range metadataCache {
			for colName, colMeta := range meta.Columns {
				if colMeta.BlindIndex != "" {
					pattern := `(?i)` + regexp.QuoteMeta(colMeta.BlindIndex) + `"?\s*=\s*\$([0-9]+)`
					re := regexp.MustCompile(pattern)
					matches := re.FindAllStringSubmatch(query, -1)
					for _, match := range matches {
						if paramIndex, err := strconv.Atoi(match[1]); err == nil {
							selectParamMap[paramIndex-1] = colMeta.BlindIndex
							LogParser.Printf("Detectado blind index busca param $%d = %s", paramIndex, colMeta.BlindIndex)
						}
					}
				}

				if colMeta.Encrypt {
					patternLike := `(?i)` + regexp.QuoteMeta(colName) + `"?\s+(?:I)?LIKE\s+\$([0-9]+)`
					reLike := regexp.MustCompile(patternLike)
					if matches := reLike.FindStringSubmatch(query); len(matches) > 1 {
						if paramIndex, err := strconv.Atoi(matches[1]); err == nil {
							filterColName = colName
							filterParamIndex = paramIndex - 1
							LogParser.Printf("Detectado LIKE intercept para coluna '%s' no param $%d", colName, paramIndex)
							replacement := fmt.Sprintf("CAST($$%d AS VARCHAR) IS NOT NULL", paramIndex)
							query = reLike.ReplaceAllString(query, replacement)

							newPayload := make([]byte, 0, len(payload))
							pos := 0
							stmtEnd := bytes.IndexByte(payload, 0)
							newPayload = append(newPayload, payload[:stmtEnd+1]...)

							newPayload = append(newPayload, []byte(query)...)
							newPayload = append(newPayload, 0)

							pos = bytes.IndexByte(payload[stmtEnd+1:], 0) + stmtEnd + 2
							newPayload = append(newPayload, payload[pos:]...)

							payload = newPayload
						}
					}
				}
			}
		}
		cacheMu.RUnlock()

		if len(selectParamMap) > 0 || filterColName != "" {
			p.statements[stmtName] = StatementMetaData{
				SelectBlindIndexMap: selectParamMap,
				FilterColName:       filterColName,
				FilterParamIndex:    filterParamIndex,
			}
		}
	}

	return payload
}

func (p *PgParser) parseBind(payload []byte) ([]byte, FilterContext) {
	pos := 0

	portalEnd := bytes.IndexByte(payload[pos:], 0)
	if portalEnd < 0 {
		return payload, FilterContext{}
	}
	portal := payload[pos : pos+portalEnd+1]
	pos += portalEnd + 1

	stmtEnd := bytes.IndexByte(payload[pos:], 0)
	if stmtEnd < 0 {
		return payload, FilterContext{}
	}
	stmtNameBytes := payload[pos : pos+stmtEnd+1]
	stmtName := string(payload[pos : pos+stmtEnd])
	pos += stmtEnd + 1

	if pos+2 > len(payload) {
		return payload, FilterContext{}
	}
	formatCount := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	formatCodes := make([]byte, formatCount*2)
	copy(formatCodes, payload[pos:pos+formatCount*2])
	pos += formatCount * 2

	if pos+2 > len(payload) {
		LogParser.Printf("Early return at paramCount check. pos=%d, len=%d", pos, len(payload))
		return payload, FilterContext{}
	}
	paramCount := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	LogParser.Printf("stmtName='%s', formatCount=%d, paramCount=%d", stmtName, formatCount, paramCount)

	params := make([][]byte, 0, paramCount)
	for i := 0; i < paramCount; i++ {
		if pos+4 > len(payload) {
			return payload, FilterContext{}
		}
		size := int(int32(binary.BigEndian.Uint32(payload[pos:])))
		pos += 4
		if size == -1 {
			params = append(params, nil)
			continue
		}
		if pos+size > len(payload) {
			return payload, FilterContext{}
		}
		params = append(params, payload[pos:pos+size])
		pos += size
	}

	rest := payload[pos:]

	stmtMeta, ok := p.statements[stmtName]
	if !ok {
		LogParser.Printf("stmtName='%s' NOT FOUND in p.statements! Available keys: %v", stmtName, getMapKeys(p.statements))
		return payload, FilterContext{}
	}

	LogParser.Printf("stmtMeta FOUND for '%s'. SelectBlindIndexMap len=%d", stmtName, len(stmtMeta.SelectBlindIndexMap))

	filterCtx := FilterContext{}

	if stmtMeta.FilterColName != "" && stmtMeta.FilterParamIndex >= 0 && stmtMeta.FilterParamIndex < len(params) {
		val := params[stmtMeta.FilterParamIndex]
		if val != nil {
			cleanVal := strings.Trim(string(val), "%")
			filterCtx = FilterContext{
				ColName: stmtMeta.FilterColName,
				Value:   cleanVal,
			}
			LogParser.Printf("Extraido filtro parcial para %s: '%s'", stmtMeta.FilterColName, cleanVal)
		}
	}

	if len(stmtMeta.SelectBlindIndexMap) > 0 {
		for idx := range stmtMeta.SelectBlindIndexMap {
			if idx < len(params) && params[idx] != nil {
				originalPlaintext := string(params[idx])
				hmacVal := computeHMAC(params[idx])
				hexHmac := hex.EncodeToString(hmacVal)
				params[idx] = []byte(hexHmac)
				LogParser.Printf("Hashing param $%d: plaintext='%s' -> hmac='%s'", idx+1, originalPlaintext, hexHmac)
			}
		}

		var newPayload []byte
		newPayload = append(newPayload, portal...)
		newPayload = append(newPayload, stmtNameBytes...)

		fcBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(fcBytes, uint16(formatCount))
		newPayload = append(newPayload, fcBytes...)
		newPayload = append(newPayload, formatCodes...)

		pcBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(pcBytes, uint16(len(params)))
		newPayload = append(newPayload, pcBytes...)

		for _, value := range params {
			if value == nil {
				s := make([]byte, 4)
				binary.BigEndian.PutUint32(s, 0xffffffff)
				newPayload = append(newPayload, s...)
			} else {
				s := make([]byte, 4)
				binary.BigEndian.PutUint32(s, uint32(len(value)))
				newPayload = append(newPayload, s...)
				newPayload = append(newPayload, value...)
			}
		}
		newPayload = append(newPayload, rest...)
		return newPayload, filterCtx
	} else if filterCtx.ColName != "" {
		return payload, filterCtx
	}

	columns := stmtMeta.Columns
	if len(columns) == 0 || len(params) != len(columns) {
		return payload, FilterContext{}
	}

	tableMeta, ok := p.getTableMeta(stmtMeta.Table)
	if !ok {
		return payload, FilterContext{}
	}

	hasEncrypted := false
	for _, col := range columns {
		if sec, exists := tableMeta.Columns[col]; exists && sec.Encrypt {
			hasEncrypted = true
			break
		}
	}
	if !hasEncrypted {
		return payload, FilterContext{}
	}

	original := make([][]byte, len(params))
	copy(original, params)

	var dek []byte
	var wrappedDek []byte
	var errDek error

	if EncryptionMode == "shared" {
		dek = SharedDEK
	} else {
		dek, wrappedDek, errDek = generateAndWrapDEK(&masterPrivateKey.PublicKey)
		if errDek != nil {
			LogParser.Printf("Erro ao gerar DEK com RSA: %v", errDek)
			return payload, FilterContext{}
		}
	}

	for i, col := range columns {
		if original[i] == nil {
			continue
		}
		sec, exists := tableMeta.Columns[col]
		if !exists || !sec.Encrypt {
			continue
		}

		encryptedData, err := encryptDataWithDEK(dek, original[i])
		if err != nil {
			LogParser.Printf("Erro criptografando '%s': %v", col, err)
			return payload, FilterContext{}
		}

		var finalPayload []byte
		if EncryptionMode == "shared" {
			finalPayload = encryptedData
		} else {
			finalPayload = append(wrappedDek, encryptedData...)
		}
		
		params[i] = []byte(hex.EncodeToString(finalPayload))
	}

	for _, bi := range stmtMeta.InsertBlindIndexes {
		if bi.SourceIndex < len(original) && original[bi.SourceIndex] != nil {
			hmacVal := computeHMAC(original[bi.SourceIndex])
			params = append(params, []byte(hex.EncodeToString(hmacVal)))
		} else {
			params = append(params, nil)
		}
	}
	var newFormatCodes []byte
	var newFormatCount = formatCount

	if formatCount == 0 || formatCount == 1 {
		newFormatCodes = formatCodes
	} else if formatCount == paramCount {
		newFormatCodes = append(newFormatCodes, formatCodes...)
		for i := 0; i < len(stmtMeta.InsertBlindIndexes); i++ {
			newFormatCodes = append(newFormatCodes, 0, 0)
		}
		newFormatCount = paramCount + len(stmtMeta.InsertBlindIndexes)
	}

	// Rebuild payload
	var newPayload []byte
	newPayload = append(newPayload, portal...)
	newPayload = append(newPayload, stmtNameBytes...)

	fcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(fcBytes, uint16(newFormatCount))
	newPayload = append(newPayload, fcBytes...)
	newPayload = append(newPayload, newFormatCodes...)

	pcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(pcBytes, uint16(len(params)))
	newPayload = append(newPayload, pcBytes...)

	for _, value := range params {
		if value == nil {
			s := make([]byte, 4)
			binary.BigEndian.PutUint32(s, 0xffffffff)
			newPayload = append(newPayload, s...)
		} else {
			s := make([]byte, 4)
			binary.BigEndian.PutUint32(s, uint32(len(value)))
			newPayload = append(newPayload, s...)
			newPayload = append(newPayload, value...)
		}
	}
	newPayload = append(newPayload, rest...)

	LogParser.Printf("Criptografado: table='%s'", stmtMeta.Table)

	return newPayload, FilterContext{}
}

func (p *PgParser) getTableMeta(table string) (TableMetadata, bool) {
	key := p.database + "." + table
	cacheMu.RLock()
	meta, ok := metadataCache[key]
	cacheMu.RUnlock()
	return meta, ok
}

func (p *PgParser) getTableNameFromOID(oid int32) (string, bool) {
	cacheMu.RLock()
	dbCache, ok := tableOIDsCache[p.database]
	if !ok {
		cacheMu.RUnlock()
		return "", false
	}
	name, ok := dbCache[oid]
	cacheMu.RUnlock()
	return name, ok
}
