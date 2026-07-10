package middleware

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func loadAllMetadata(dbConn net.Conn, database string) error {
	query := `SELECT COALESCE(cls.oid, 0), c.table_name, c.column_name, COALESCE(d.description, '') ` +
		`FROM information_schema.columns c ` +
		`LEFT JOIN pg_class cls ON cls.relname = c.table_name ` +
		`LEFT JOIN pg_namespace ns ON ns.oid = cls.relnamespace AND ns.nspname = c.table_schema ` +
		`LEFT JOIN pg_description d ON d.objoid = cls.oid AND d.objsubid = c.ordinal_position ` +
		`WHERE c.table_schema = 'public'`

	if err := sendSimpleQuery(dbConn, query); err != nil {
		return fmt.Errorf("Enviando query: %w", err)
	}

	results := make(map[string]*TableMetadata)

	for {
		mt, pl, err := readWireMessage(dbConn)
		if err != nil {
			return fmt.Errorf("Lendo resposta: %w", err)
		}

		switch mt {
		case 'T':
		case 'D':
			vals := parseDataRow(pl)
			if len(vals) >= 4 {
				oidStr := vals[0]
				tableName := vals[1]
				columnName := vals[2]
				comment := vals[3]

				oidInt, _ := strconv.Atoi(oidStr)
				oid := int32(oidInt)

				cacheMu.Lock()
				if tableOIDsCache[database] == nil {
					tableOIDsCache[database] = make(map[int32]string)
				}
				tableOIDsCache[database][oid] = tableName
				cacheMu.Unlock()

				if _, ok := results[tableName]; !ok {
					results[tableName] = &TableMetadata{
						Columns: make(map[string]ColumnSecurity),
					}
				}

				info := ColumnSecurity{}
				if strings.Contains(comment, "middleware:encrypt") {
					info.Encrypt = true
					info.Mode = "aes-gcm"
				}

				parts := strings.Split(comment, " ")
				for _, p := range parts {
					if strings.HasPrefix(p, "middleware:blind_index=") {
						info.BlindIndex = strings.TrimPrefix(p, "middleware:blind_index=")
					}
				}

				results[tableName].Columns[columnName] = info
			}

		case 'C':

		case 'E':
			LogMetadata.Printf("Erro do PostgreSQL na query")

		case 'Z':
			cacheMu.Lock()
			for table, meta := range results {
				key := database + "." + table
				metadataCache[key] = *meta
				for col, sec := range meta.Columns {
					if sec.Encrypt {
						LogMetadata.Printf(" '%s.%s' gateway:encrypt", table, col)
					}
				}
			}
			cacheMu.Unlock()

			if len(results) == 0 {
				LogMetadata.Println("Nenhuma tabela encontrada no schema public")
			}
			return nil
		}
	}
}
