package worker

import (
	"crypto/tls"
	"go.k6.io/k6/js/modules"
	"log"
	"net"
)

func init() {
	modules.Register("k6/x/raw-http", new(result))
}

type result struct{}

func (result *result) ConnectTLS(addr string) (net.Conn, error) {
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

func (result *result) ConnectTCP(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (result *result) Write(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func (result *result) Read(conn net.Conn, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (result *result) Close(conn net.Conn) error {
	err := conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (result *result) SendClientHello() {
	conn := Conn{}
	conn.MakeClientHello()
}
