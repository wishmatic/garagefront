package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Host string
	Port int
}

func Load() Config {
	port := 8080
	if v, err := strconv.Atoi(os.Getenv("PORT")); err == nil {
		port = v
	}

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	return Config{
		Host: host,
		Port: port,
	}
}

func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
