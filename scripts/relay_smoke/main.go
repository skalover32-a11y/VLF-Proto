package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"vlf-runtime/internal/auth"
)

type openReq struct {
	Proto   string            `json:"proto"`
	DstHost string            `json:"dst_host"`
	DstPort int               `json:"dst_port"`
	Meta    map[string]string `json:"meta,omitempty"`
}

type openResp struct {
	ConnID string `json:"conn_id"`
}

type sendResp struct {
	Accepted int `json:"accepted"`
}

type closeResp struct {
	Closed bool `json:"closed"`
}

func main() {
	baseURL := envOr("GATEWAY_URL", "http://localhost:8080")
	clientID := envOr("VLF_CLIENT_ID", "smoke-client")
	secret := envOr("VLF_SECRET", "smoke-secret")
	dstHost := envOr("DST_HOST", "tcp-echo")
	dstPort := envOrInt("DST_PORT", 9000)

	parsed, err := url.Parse(baseURL)
	if err != nil {
		log.Fatalf("invalid GATEWAY_URL: %v", err)
	}
	baseURL = strings.TrimRight(parsed.String(), "/")

	httpClient := &http.Client{Timeout: 10 * time.Second}

	openBody, _ := json.Marshal(openReq{
		Proto:   "tcp",
		DstHost: dstHost,
		DstPort: dstPort,
		Meta: map[string]string{
			"app":      "relay_smoke",
			"flow_tag": "auto",
			"net_hint": "wifi",
		},
	})

	var opResp openResp
	if err := doJSON(httpClient, baseURL, clientID, secret, http.MethodPost, "/v1/relay/open", openBody, &opResp); err != nil {
		log.Fatalf("relay open failed: %v", err)
	}
	if opResp.ConnID == "" {
		log.Fatalf("relay open returned empty conn_id")
	}

	payload := []byte(fmt.Sprintf("relay-smoke-payload-%d", time.Now().UnixNano()))

	var sResp sendResp
	sendPath := fmt.Sprintf("/v1/relay/send?conn_id=%s", url.QueryEscape(opResp.ConnID))
	if err := doJSON(httpClient, baseURL, clientID, secret, http.MethodPost, sendPath, payload, &sResp); err != nil {
		log.Fatalf("relay send failed: %v", err)
	}
	if sResp.Accepted <= 0 {
		log.Fatalf("relay send accepted=%d", sResp.Accepted)
	}

	recvPath := fmt.Sprintf("/v1/relay/recv?conn_id=%s&max=32768", url.QueryEscape(opResp.ConnID))
	recvDeadline := time.Now().Add(8 * time.Second)
	recvOK := false
	for time.Now().Before(recvDeadline) {
		data, eos, status, err := doRecv(httpClient, baseURL, clientID, secret, recvPath)
		if err != nil {
			log.Fatalf("relay recv failed: %v", err)
		}
		if status == http.StatusNoContent {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		if status != http.StatusOK {
			log.Fatalf("relay recv status=%d", status)
		}
		if bytes.Equal(data, payload) {
			recvOK = true
			_ = eos
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	if !recvOK {
		log.Fatalf("relay recv did not return expected echo")
	}

	var cResp closeResp
	closePath := fmt.Sprintf("/v1/relay/close?conn_id=%s", url.QueryEscape(opResp.ConnID))
	if err := doJSON(httpClient, baseURL, clientID, secret, http.MethodPost, closePath, nil, &cResp); err != nil {
		log.Fatalf("relay close failed: %v", err)
	}
	if !cResp.Closed {
		log.Fatalf("relay close returned closed=false")
	}

	fmt.Println("PASS relay smoke")
}

func doJSON(client *http.Client, baseURL, clientID, secret, method, fullPath string, body []byte, out any) error {
	req, err := signedRequest(baseURL, clientID, secret, method, fullPath, body)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode json: %w, body=%s", err, string(raw))
		}
	}
	return nil
}

func doRecv(client *http.Client, baseURL, clientID, secret, fullPath string) ([]byte, bool, int, error) {
	req, err := signedRequest(baseURL, clientID, secret, http.MethodGet, fullPath, nil)
	if err != nil {
		return nil, false, 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, 0, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNoContent {
		return nil, false, resp.StatusCode, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, resp.StatusCode, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}

	eos := resp.Header.Get("X-VLF-EOS") == "1"
	return raw, eos, resp.StatusCode, nil
}

func signedRequest(baseURL, clientID, secret, method, fullPath string, body []byte) (*http.Request, error) {
	if body == nil {
		body = []byte{}
	}

	signedPath := fullPath
	if idx := strings.IndexByte(fullPath, '?'); idx >= 0 {
		signedPath = fullPath[:idx]
	}

	ts := time.Now().UnixMilli()
	nonce, err := randomHex(8)
	if err != nil {
		return nil, err
	}

	bodyHash := auth.HashBody(body)
	material := fmt.Sprintf("%s|%s|%d|%s|%s", method, signedPath, ts, nonce, bodyHash)
	sig := signHex(secret, material)

	req, err := http.NewRequest(method, baseURL+fullPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-VLF-Client", clientID)
	req.Header.Set("X-VLF-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-VLF-Nonce", nonce)
	req.Header.Set("X-VLF-Sig", sig)
	if method == http.MethodPost {
		if json.Valid(body) {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
	}

	return req, nil
}

func signHex(secret string, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envOrInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
