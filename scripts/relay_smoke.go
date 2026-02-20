package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

type openReq struct {
	Proto   string            `json:"proto"`
	DstHost string            `json:"dst_host"`
	DstPort int               `json:"dst_port"`
	SNI     string            `json:"sni,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
}

type openResp struct {
	ConnID string `json:"conn_id"`
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustAtoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "RELAY SMOKE: FAIL ❌: "+format+"\n", args...)
	os.Exit(1)
}

func bodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// sig = hex(HMAC_SHA256(secret, `method|path|ts|nonce|body_hash`))
func makeSig(secret, method, path string, tsMs int64, nonce string, body []byte) string {
	payload := fmt.Sprintf("%s|%s|%d|%s|%s", method, path, tsMs, nonce, bodyHashHex(body))
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func addAuthHeaders(req *http.Request, clientID, secret string, body []byte) {
	tsMs := time.Now().UnixMilli()
	nonce := fmt.Sprintf("%d-%d", tsMs, time.Now().UnixNano())

	sig := makeSig(secret, req.Method, req.URL.Path, tsMs, nonce, body)

	req.Header.Set("X-VLF-Client", clientID)
	req.Header.Set("X-VLF-TS", strconv.FormatInt(tsMs, 10))
	req.Header.Set("X-VLF-Nonce", nonce)
	req.Header.Set("X-VLF-Sig", sig)
}

func main() {
	// run inside compose network:
	// RELAY_BASE=http://gateway:8080 RELAY_DIAL_HOST=tcp-echo RELAY_DIAL_PORT=9000
	base := env("RELAY_BASE", "http://gateway:8080")
	dialHost := env("RELAY_DIAL_HOST", "tcp-echo")
	dialPort := mustAtoi(env("RELAY_DIAL_PORT", "9000"), 9000)

	clientID := env("VLF_CLIENT", "smoke-client")
	secret := env("VLF_SECRET", "smoke-secret")

	client := &http.Client{Timeout: 10 * time.Second}

	// OPEN
	openBody, _ := json.Marshal(openReq{
		Proto:   "tcp",
		DstHost: dialHost,
		DstPort: dialPort,
		Meta: map[string]string{
			"app": "relay_smoke_go",
		},
	})

	openURL := base + "/v1/relay/open"
	req, _ := http.NewRequest("POST", openURL, bytes.NewReader(openBody))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, clientID, secret, openBody)

	resp, err := client.Do(req)
	if err != nil {
		fail("open error: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		fail("open status=%d body=%s", resp.StatusCode, string(data))
	}
	var o openResp
	if err := json.Unmarshal(data, &o); err != nil {
		fail("open decode: %v body=%s", err, string(data))
	}
	if o.ConnID == "" {
		fail("empty conn_id")
	}

	// SEND
	payload := []byte("VLF_RELAY_SMOKE_PING\n")
	sendURL := base + "/v1/relay/send?conn_id=" + o.ConnID
	sreq, _ := http.NewRequest("POST", sendURL, bytes.NewReader(payload))
	sreq.Header.Set("Content-Type", "application/octet-stream")
	addAuthHeaders(sreq, clientID, secret, payload)

	sresp, err := client.Do(sreq)
	if err != nil {
		fail("send error: %v", err)
	}
	io.Copy(io.Discard, sresp.Body)
	sresp.Body.Close()
	if sresp.StatusCode != 200 {
		fail("send status=%d", sresp.StatusCode)
	}

	// RECV (пока не увидим echo)
	var got []byte
	for i := 0; i < 30; i++ {
		recvURL := base + "/v1/relay/recv?conn_id=" + o.ConnID + "&max=32768"
		rreq, _ := http.NewRequest("GET", recvURL, nil)
		addAuthHeaders(rreq, clientID, secret, nil)

		rresp, err := client.Do(rreq)
		if err != nil {
			fail("recv error: %v", err)
		}
		b, _ := io.ReadAll(rresp.Body)
		rresp.Body.Close()

		if rresp.StatusCode == 204 {
			time.Sleep(120 * time.Millisecond)
			continue
		}
		if rresp.StatusCode != 200 {
			fail("recv status=%d body=%s", rresp.StatusCode, string(b))
		}
		got = append(got, b...)
		if bytes.Contains(got, payload) {
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	if !bytes.Contains(got, payload) {
		fail("no echo received. got=%q", string(got))
	}

	// CLOSE
	closeURL := base + "/v1/relay/close?conn_id=" + o.ConnID
	creq, _ := http.NewRequest("POST", closeURL, bytes.NewReader([]byte("{}")))
	creq.Header.Set("Content-Type", "application/json")
	addAuthHeaders(creq, clientID, secret, []byte("{}"))

	cresp, err := client.Do(creq)
	if err != nil {
		fail("close error: %v", err)
	}
	io.Copy(io.Discard, cresp.Body)
	cresp.Body.Close()
	if cresp.StatusCode != 200 {
		fail("close status=%d", cresp.StatusCode)
	}

	fmt.Println("RELAY SMOKE: PASS ✅")
}
