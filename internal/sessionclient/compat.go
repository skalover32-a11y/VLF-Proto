package sessionclient

import (
	"errors"
	"io"
	"strings"
)

var (
	errLegacyPeerAuthUnsupported = errors.New("legacy peer rejected extended auth")
	ErrProfileSwitchUnsupported  = errors.New("transport profile migration unsupported by peer")
)

func isLegacyAuthUnsupportedReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return strings.Contains(reason, "invalid auth payload") ||
		strings.Contains(reason, "trailing bytes in auth payload")
}

func isLegacyAuthCloseBeforeOK(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "application error 0x0") ||
		strings.Contains(msg, "stream reset") ||
		strings.Contains(msg, "stream canceled") ||
		strings.Contains(msg, "connection closed") ||
		strings.Contains(msg, "closed the connection") ||
		strings.Contains(msg, "closed locally") ||
		strings.Contains(msg, "closed by peer")
}

func normalizeUnsupportedProfileReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "peer does not support profile migration"
	}
	return reason
}
