package middleware

import "net"

type ColumnSecurity struct {
	Encrypt    bool
	Mode       string
	BlindIndex string
}

type TableMetadata struct {
	Columns map[string]ColumnSecurity
}

type BlindIndexGen struct {
	SourceIndex int
}

type StatementMetaData struct {
	Table               string
	Columns             []string
	InsertBlindIndexes  []BlindIndexGen
	SelectBlindIndexMap map[int]string
	FilterColName       string
	FilterParamIndex    int
}

type FilterContext struct {
	ColName string
	Value   string
}

type PgParser struct {
	statements map[string]StatementMetaData
	database   string
}

type DecryptTarget struct {
	ColIndex  int
	TableName string
}

type BufferedMsg struct {
	Type    byte
	Payload []byte
}

type Session struct {
	clientConn net.Conn
	dbConn     net.Conn
	parser     *PgParser

	intercepting   bool
	decryptTargets []DecryptTarget

	filterColName  string
	filterColIndex int
	filterValue    string
	rowsSent       int32
}
