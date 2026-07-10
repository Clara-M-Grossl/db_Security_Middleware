package middleware

import (
	"log"
	"os"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

var (
	LogMain     = log.New(os.Stdout, ColorGreen+"[MAIN] "+ColorReset, log.LstdFlags)
	LogSession  = log.New(os.Stdout, ColorBlue+"[SESSION] "+ColorReset, log.LstdFlags)
	LogParser   = log.New(os.Stdout, ColorPurple+"[PARSER] "+ColorReset, log.LstdFlags)
	LogVault    = log.New(os.Stdout, ColorYellow+"[VAULT] "+ColorReset, log.LstdFlags)
	LogMetadata = log.New(os.Stdout, ColorCyan+"[METADATA] "+ColorReset, log.LstdFlags)
	LogCrypto   = log.New(os.Stdout, ColorRed+"[CRYPTO] "+ColorReset, log.LstdFlags)
)
