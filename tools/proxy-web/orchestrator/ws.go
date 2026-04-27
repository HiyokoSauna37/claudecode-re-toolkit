package orchestrator

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// WSFrame represents a parsed WebSocket frame
type WSFrame struct {
	Opcode     int             `json:"opcode"`
	Fin        bool            `json:"fin"`
	Length     int             `json:"length"`
	Text       string          `json:"text,omitempty"`
	JSON       json.RawMessage `json:"json,omitempty"`
	Hex        string          `json:"hex,omitempty"`
}

// WSResult contains the capture results
type WSResult struct {
	Target     string            `json:"target"`
	StartTime  string            `json:"capture_start"`
	EndTime    string            `json:"capture_end,omitempty"`
	Duration   int               `json:"duration_seconds"`
	RawBytes   int               `json:"raw_bytes"`
	Frames     int               `json:"frames_count"`
	Messages   []json.RawMessage `json:"messages"`
	MsgTypes   map[string]int    `json:"message_types"`
	Headers    string            `json:"handshake_headers,omitempty"`
	Error      string            `json:"error,omitempty"`
}

func wsHandshake(host string, port string, path string, timeout time.Duration) (net.Conn, string, []byte, error) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, "", nil, fmt.Errorf("connection failed: %w", err)
	}

	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n",
		path, addr, key,
	)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(request))
	if err != nil {
		conn.Close()
		return nil, "", nil, fmt.Errorf("write failed: %w", err)
	}

	// Read response with separate read deadline
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	var response []byte
	for {
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, "", nil, fmt.Errorf("read failed: %w", err)
		}
		response = append(response, buf[:n]...)
		if idx := strings.Index(string(response), "\r\n\r\n"); idx != -1 {
			headers := string(response[:idx])
			extra := response[idx+4:]
			if !strings.Contains(headers, "101") {
				conn.Close()
				firstLine := strings.SplitN(headers, "\r\n", 2)[0]
				return nil, "", nil, fmt.Errorf("upgrade failed: %s", firstLine)
			}
			// Clear deadline after successful handshake
			conn.SetDeadline(time.Time{})
			return conn, headers, extra, nil
		}
	}
}

func parseWSFrames(data []byte) []WSFrame {
	var frames []WSFrame
	pos := 0
	for pos < len(data) {
		if pos+2 > len(data) {
			break
		}
		byte0 := data[pos]
		byte1 := data[pos+1]
		fin := (byte0 & 0x80) != 0
		opcode := int(byte0 & 0x0F)
		masked := (byte1 & 0x80) != 0
		payloadLen := int(byte1 & 0x7F)
		pos += 2

		if payloadLen == 126 {
			if pos+2 > len(data) {
				break
			}
			payloadLen = int(binary.BigEndian.Uint16(data[pos : pos+2]))
			pos += 2
		} else if payloadLen == 127 {
			if pos+8 > len(data) {
				break
			}
			payloadLen = int(binary.BigEndian.Uint64(data[pos : pos+8]))
			pos += 8
		}

		if masked {
			if pos+4 > len(data) {
				break
			}
			pos += 4 // skip mask key (server frames are not masked)
		}

		var payload []byte
		if pos+payloadLen > len(data) {
			payload = data[pos:]
			pos = len(data)
		} else {
			payload = data[pos : pos+payloadLen]
			pos += payloadLen
		}

		frame := WSFrame{Opcode: opcode, Fin: fin, Length: len(payload)}
		if opcode == 1 { // Text frame
			text := string(payload)
			frame.Text = text
			var raw json.RawMessage
			if json.Unmarshal(payload, &raw) == nil {
				frame.JSON = raw
			}
		} else if opcode == 2 && len(payload) > 0 { // Binary
			hexLen := 64
			if len(payload) < hexLen {
				hexLen = len(payload)
			}
			frame.Hex = fmt.Sprintf("%x", payload[:hexLen])
		}
		frames = append(frames, frame)
	}
	return frames
}

// RunWSProbe checks if a WebSocket endpoint accepts connections
func RunWSProbe(targetURL string) {
	targetURL = Refang(targetURL)
	host, port, path := parseWSURL(targetURL)

	fmt.Printf("%s=== WebSocket Probe: %s ===%s\n", cCyan, targetURL, cReset)

	conn, headers, extra, err := wsHandshake(host, port, path, 10*time.Second)
	if err != nil {
		fmt.Printf("  [%sCLOSED%s] %s\n", cRed, cReset, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("  [%sOPEN%s] WebSocket upgrade accepted\n", cGreen, cReset)
	for _, line := range strings.Split(headers, "\r\n") {
		if line != "" {
			fmt.Printf("  %s%s%s\n", cGray, line, cReset)
		}
	}

	// Try to read first messages
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _ := conn.Read(buf)
	allData := append(extra, buf[:n]...)

	frames := parseWSFrames(allData)
	msgTypes := map[string]int{}
	for _, f := range frames {
		if f.JSON != nil {
			var msg map[string]interface{}
			if json.Unmarshal(f.JSON, &msg) == nil {
				if t, ok := msg["type"].(string); ok {
					msgTypes[t]++
				}
			}
		}
	}

	if len(msgTypes) > 0 {
		fmt.Printf("\n  %sMessage types:%s ", cCyan, cReset)
		parts := []string{}
		for t, c := range msgTypes {
			parts = append(parts, fmt.Sprintf("%s(%d)", t, c))
		}
		fmt.Println(strings.Join(parts, ", "))
	}
	fmt.Printf("  Frames received: %d\n", len(frames))
}

// RunWSCapture captures WebSocket messages for specified duration
func RunWSCapture(targetURL string, duration int, outputJSON bool) {
	targetURL = Refang(targetURL)
	host, port, path := parseWSURL(targetURL)

	result := WSResult{
		Target:    targetURL,
		StartTime: time.Now().UTC().Format(time.RFC3339),
		Duration:  duration,
		MsgTypes:  map[string]int{},
	}

	conn, headers, extra, err := wsHandshake(host, port, path, 15*time.Second)
	if err != nil {
		result.Error = err.Error()
		if outputJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(result)
		} else {
			fmt.Fprintf(os.Stderr, "  [%sFAIL%s] %s\n", cRed, cReset, err)
		}
		os.Exit(1)
	}
	result.Headers = headers

	if !outputJSON {
		fmt.Fprintf(os.Stderr, "  [%sOK%s] Connected. Capturing %ds...\n", cGreen, cReset, duration)
	}

	rawData := make([]byte, len(extra))
	copy(rawData, extra)

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	buf := make([]byte, 65536)

	for time.Now().Before(endTime) {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}
		rawData = append(rawData, buf[:n]...)
	}
	conn.Close()

	result.EndTime = time.Now().UTC().Format(time.RFC3339)
	result.RawBytes = len(rawData)

	frames := parseWSFrames(rawData)
	result.Frames = len(frames)

	for _, f := range frames {
		if f.JSON != nil {
			result.Messages = append(result.Messages, f.JSON)
			var msg map[string]interface{}
			if json.Unmarshal(f.JSON, &msg) == nil {
				if t, ok := msg["type"].(string); ok {
					result.MsgTypes[t]++
				}
			}
		}
	}

	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(result)
	} else {
		fmt.Printf("\n%s=== WebSocket Capture Complete ===%s\n", cCyan, cReset)
		fmt.Printf("  Raw bytes: %d\n", result.RawBytes)
		fmt.Printf("  Frames: %d\n", result.Frames)
		fmt.Printf("  Messages: %d\n", len(result.Messages))
		fmt.Printf("  Types: %v\n", result.MsgTypes)
	}
}

func parseWSURL(raw string) (host, port, path string) {
	raw = strings.TrimPrefix(raw, "ws://")
	raw = strings.TrimPrefix(raw, "wss://")

	path = "/"
	if idx := strings.Index(raw, "/"); idx != -1 {
		path = raw[idx:]
		raw = raw[:idx]
	}

	host = raw
	port = "80"
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		host = raw[:idx]
		port = raw[idx+1:]
	}
	return
}
