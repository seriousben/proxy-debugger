package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const protocolV2HeaderLen = 16

var (
	protocolV1SignatureBytes = []byte("PROXY")
	protocolV2SignatureBytes = []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")

	htmlTpl = template.Must(template.New("html").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>PROXY Protocol Debugger</title>
	</head>
	<body>
		{{if (gt (len .) 0)}}
            <table border="1">
            <tr>
				<th>Version</th>
				<th>AddrType</th>
				<th>SrcAddr</th>
				<th>DstAddr</th>
				<th>Transport Protocol (v2)</th>
				<th>Command (v2)</th>
            </tr>
			{{range .}}
            <tr>
				<td>{{.Version}}</td>
				<td>{{.AddrType}}</td>
				<td>{{.SrcAddr}}:{{.SrcPort}}</td>
				<td>{{.DstAddr}}:{{.DstPort}}</td>
				<td>{{.TransportProtocol}}</td>
				<td>{{.Command}}</td>
            </tr>
			{{end}}
            </table>
        {{else}}
            <p>No PROXY protocol header</p>
		{{end}}
	</body>
</html>
`))
)

type protocol struct {
	Version           string
	Command           string
	AddrType          string
	TransportProtocol string
	SrcAddr           string
	SrcPort           string
	DstAddr           string
	DstPort           string
}

func parseV1(bufReader *bufio.Reader) (protocol, error) {
	line, isPrefix, err := bufReader.ReadLine()
	if err != nil {
		return protocol{}, fmt.Errorf("v1 readLine error: %w", err)
	}
	if isPrefix {
		return protocol{}, fmt.Errorf("v1 proxy-protocol v1 line too long")
	}

	// remove \r
	line = line[:len(line)-1]

	sections := bytes.Split(line, []byte("\x20"))
	if len(sections) != 6 {
		return protocol{}, fmt.Errorf("proxy-protocol v1 header corrupted, not enough sections (got: %d, want: %d)", len(sections), 6)
	}

	return protocol{
		Version:  "1",
		AddrType: string(sections[1]),
		SrcAddr:  string(sections[2]),
		DstAddr:  string(sections[3]),
		SrcPort:  string(sections[4]),
		DstPort:  string(sections[5]),
	}, nil
}

func parseV2(sigBytes []byte, bufReader *bufio.Reader) (protocol, error) {
	if sigBytes[12]>>4 != 0x2 {
		return protocol{}, errors.New("unknown version of protocol")
	}

	lenField := sigBytes[14:16]
	lenInt := binary.BigEndian.Uint16(lenField)
	hdrLenInt := 16 + lenInt

	// Consume the whole header
	line := make([]byte, hdrLenInt)
	_, err := io.ReadFull(bufReader, line)
	if err != nil {
		return protocol{}, err
	}

	p := protocol{
		Version: "2",
	}

	c := line[12] & 0x01

	switch c {
	case 0x0:
		p.Command = "LOCAL"
	case 0x1:
		p.Command = "PROXY"
	default:
		return protocol{}, errors.New("unknown version 2 command")
	}

	af := line[13] >> 4

	switch af {
	case 0x0:
		p.AddrType = "AF_UNSPEC"
	case 0x1:
		p.AddrType = "AF_INET"
	case 0x2:
		p.AddrType = "AF_INET6"
	case 0x3:
		p.AddrType = "AF_UNIX"
	default:
		return protocol{}, errors.New("unknown version 2 address family")
	}

	tp := line[13] & 0x01 // is it better to compare `<< 4 == 0x10`?

	switch tp {
	case 0x0:
		p.TransportProtocol = "UNSPEC"
	case 0x1:
		p.TransportProtocol = "STREAM"
	case 0x2:
		p.TransportProtocol = "DGRAM"
	default:
		return protocol{}, errors.New("unknown version 2 transport protocol")
	}

	switch line[13] {
	case 0x00:
		p.SrcAddr = "UNSPEC"
		p.SrcPort = "UNSPEC"
		p.DstAddr = "UNSPEC"
		p.DstPort = "UNSPEC"
	case 0x11:
		p.SrcAddr = net.IP(line[16:20]).String()
		p.DstAddr = net.IP(line[20:24]).String()
		p.SrcPort = strconv.FormatUint(uint64(binary.BigEndian.Uint16(line[24:26])), 10)
		p.DstPort = strconv.FormatUint(uint64(binary.BigEndian.Uint16(line[26:28])), 10)
	case 0x21:
		p.SrcAddr = net.IP(line[16:32]).String()
		p.DstAddr = net.IP(line[32:48]).String()
		p.SrcPort = strconv.FormatUint(uint64(binary.BigEndian.Uint16(line[48:50])), 10)
		p.DstPort = strconv.FormatUint(uint64(binary.BigEndian.Uint16(line[50:52])), 10)
	default:
		return protocol{}, errors.New("unknown version 2 transport protocol")
	}

	return p, nil
}

func maybeParseProxyProtocols(bufReader *bufio.Reader) ([]protocol, error) {
	var pps []protocol

	for {
		sigBytes, err := bufReader.Peek(protocolV2HeaderLen)
		if err != nil {
			return nil, fmt.Errorf("peek error: %w", err)
		}

		isV1 := len(sigBytes) >= len(protocolV1SignatureBytes) && bytes.Equal(sigBytes[:len(protocolV1SignatureBytes)], protocolV1SignatureBytes)
		isV2 := len(sigBytes) >= protocolV2HeaderLen && bytes.Equal(sigBytes[:len(protocolV2SignatureBytes)], protocolV2SignatureBytes)

		log.Println(len(pps), "isV1", isV1, "isV2", isV2)

		var p protocol
		if isV1 {
			p, err = parseV1(bufReader)
		} else if isV2 {
			p, err = parseV2(sigBytes, bufReader)
		} else {
			break
		}

		if err != nil {
			return nil, err
		}
		pps = append(pps, p)
	}

	return pps, nil
}

func createResponse(req *http.Request, content string) *http.Response {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		Request:       req,
		Close:         true,
		Body:          ioutil.NopCloser(strings.NewReader(content)),
		ContentLength: int64(len(content)),
	}
}

func handleConnection(conn net.Conn) {
	log.Println("Handling new connection...")

	// Close connection when this function ends
	defer func() {
		log.Println("Closing connection...")
		conn.Close()
	}()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	bufReader := bufio.NewReader(conn)

	pps, err := maybeParseProxyProtocols(bufReader)
	if err != nil {
		log.Println("error parsing PROXY protocol:", err)
		return
	}

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		log.Println("error reading HTTP request:", err)
		return
	}

	var buf bytes.Buffer
	if err := htmlTpl.Execute(&buf, pps); err != nil {
		log.Println("error generating HTML template:", err)
		return
	}

	res := createResponse(req, buf.String())

	err = res.Write(conn)
	if err != nil {
		log.Println("error writing HTTP response:", err)
		return
	}
}

func main() {
	// listen on port
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConnection(conn)
	}
}
