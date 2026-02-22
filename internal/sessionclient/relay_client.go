package sessionclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vlf-runtime/internal/auth"
)

type relayClient struct {
	cfg        Config
	httpClient *http.Client
	baseURL    string
}

type relayTCPFlow struct {
	id      uint64
	connID  string
	client  *relayClient
	readBuf bytes.Buffer
	bufMu   sync.Mutex

	closeOnce sync.Once
}

type relayOpenResponse struct {
	ConnID string `json:"conn_id"`
}

type relaySendResponse struct {
	Accepted int `json:"accepted"`
}

func dialRelay(_ context.Context, cfg Config, httpClient *http.Client) (*relayClient, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	baseURL := strings.TrimRight(cfg.RelayBase, "/")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:8080", cfg.GatewayHost)
	}
	return &relayClient{
		cfg:        cfg,
		httpClient: httpClient,
		baseURL:    baseURL,
	}, nil
}

func (c *relayClient) openTCPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (TCPFlow, error) {
	bodyRaw, _ := json.Marshal(map[string]any{
		"proto":    "tcp",
		"dst_host": dstHost,
		"dst_port": dstPort,
		"meta": map[string]string{
			"app": "proto_bench",
		},
	})

	var openResp relayOpenResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/relay/open", bodyRaw, &openResp); err != nil {
		return nil, err
	}
	if openResp.ConnID == "" {
		return nil, fmt.Errorf("relay open returned empty conn_id")
	}

	return &relayTCPFlow{
		id:     flowID,
		connID: openResp.ConnID,
		client: c,
	}, nil
}

func (c *relayClient) openUDPFlow(_ context.Context, _ uint64, _ string, _ int) (UDPFlow, error) {
	return nil, fmt.Errorf("udp is not supported in relay transport")
}

func (c *relayClient) close() error {
	return nil
}

func (c *relayClient) probeRTT(context.Context) (time.Duration, error) {
	return 0, ErrRTTProbeUnsupported
}

func (f *relayTCPFlow) ID() uint64 {
	return f.id
}

func (f *relayTCPFlow) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	fullPath := "/v1/relay/send?conn_id=" + url.QueryEscape(f.connID)
	var sendResp relaySendResponse
	if err := f.client.doJSON(context.Background(), http.MethodPost, fullPath, p, &sendResp); err != nil {
		return 0, err
	}
	if sendResp.Accepted <= 0 {
		return 0, fmt.Errorf("relay send accepted=0")
	}
	return len(p), nil
}

func (f *relayTCPFlow) Read(p []byte) (int, error) {
	f.bufMu.Lock()
	if f.readBuf.Len() > 0 {
		n, _ := f.readBuf.Read(p)
		f.bufMu.Unlock()
		return n, nil
	}
	f.bufMu.Unlock()

	for attempt := 0; attempt < 100; attempt++ {
		fullPath := "/v1/relay/recv?conn_id=" + url.QueryEscape(f.connID) + "&max=32768"
		req, err := f.client.signedRequest(context.Background(), http.MethodGet, fullPath, nil)
		if err != nil {
			return 0, err
		}

		resp, err := f.client.httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusNoContent {
			time.Sleep(30 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("relay recv status=%d body=%s", resp.StatusCode, string(raw))
		}

		f.bufMu.Lock()
		_, _ = f.readBuf.Write(raw)
		n, _ := f.readBuf.Read(p)
		f.bufMu.Unlock()
		return n, nil
	}

	return 0, io.EOF
}

func (f *relayTCPFlow) Close() error {
	f.closeOnce.Do(func() {
		fullPath := "/v1/relay/close?conn_id=" + url.QueryEscape(f.connID)
		_, _ = f.client.doRaw(context.Background(), http.MethodPost, fullPath, []byte("{}"))
	})
	return nil
}

func (c *relayClient) doJSON(ctx context.Context, method, fullPath string, body []byte, out any) error {
	raw, err := c.doRaw(ctx, method, fullPath, body)
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode json: %w body=%s", err, string(raw))
		}
	}
	return nil
}

func (c *relayClient) doRaw(ctx context.Context, method, fullPath string, body []byte) ([]byte, error) {
	req, err := c.signedRequest(ctx, method, fullPath, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func (c *relayClient) signedRequest(ctx context.Context, method, fullPath string, body []byte) (*http.Request, error) {
	if body == nil {
		body = []byte{}
	}

	signedPath := fullPath
	if idx := strings.IndexByte(fullPath, '?'); idx >= 0 {
		signedPath = fullPath[:idx]
	}

	ts := time.Now().UnixMilli()
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	bodyHash := auth.HashBody(body)
	material := fmt.Sprintf("%s|%s|%d|%s|%s", method, signedPath, ts, nonce, bodyHash)
	sig := signHex(c.cfg.Secret, material)

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+fullPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-VLF-Client", c.cfg.ClientID)
	req.Header.Set("X-VLF-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-VLF-Nonce", nonce)
	req.Header.Set("X-VLF-Sig", sig)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return req, nil
}

func signHex(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
