package tls

import (
	"crypto/tls"
	"go.k6.io/k6/js/modules"
	"log"
	"net"
)

func init() {
	modules.Register("k6/x/tls", new(result))
}

type result struct{}

func (result *result) Connect(addr string) (net.Conn, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return conn, nil
}
