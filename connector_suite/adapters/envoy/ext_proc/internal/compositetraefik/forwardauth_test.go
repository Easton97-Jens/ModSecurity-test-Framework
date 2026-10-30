package compositetraefik

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

func TestForwardedMetadataAcceptsLongCommaSeparatedURI(t *testing.T) {
	uri := "/route?allow=a,b&" + strings.Repeat("x", (64<<10)-len("/route?allow=a,b&")-1)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	for name, value := range map[string]string{
		"X-Forwarded-Method": http.MethodGet,
		"X-Forwarded-Uri":    uri,
		"X-Forwarded-Proto":  "http",
		"X-Forwarded-Host":   "example.test",
		"X-Forwarded-For":    "127.0.0.1",
	} {
		req.Header.Set(name, value)
	}
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182}))
	metadata, err := forwardedMetadata(req)
	if err != nil || metadata.URI != uri {
		t.Fatalf("long URI metadata = %#v, err=%v", metadata, err)
	}
}

func TestForwardedMetadataRejectsURIOverReservationLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	for name, value := range map[string]string{
		"X-Forwarded-Method": http.MethodGet,
		"X-Forwarded-Uri":    "/" + strings.Repeat("x", 64<<10),
		"X-Forwarded-Proto":  "http",
		"X-Forwarded-Host":   "example.test",
		"X-Forwarded-For":    "127.0.0.1",
	} {
		req.Header.Set(name, value)
	}
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182}))
	if _, err := forwardedMetadata(req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized URI error = %v", err)
	}
}

type snapshotP1Engine struct {
	headers    []processor.Header
	bodyCalls  int
	denyStatus int
	openCalls  int
}

func (e *snapshotP1Engine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	e.openCalls++
	return &snapshotP1Tx{engine: e}, nil
}

type snapshotP1Tx struct{ engine *snapshotP1Engine }

func (t *snapshotP1Tx) ProcessHeaders(_ context.Context, direction processor.Direction, headers []processor.Header, _ bool) (processor.Decision, error) {
	if direction != processor.DirectionRequest {
		return processor.Decision{Action: processor.ActionAllow}, nil
	}
	t.engine.headers = make([]processor.Header, len(headers))
	for i, header := range headers {
		t.engine.headers[i] = processor.Header{Name: header.Name, Value: append([]byte(nil), header.Value...)}
		if header.Name == "x-msconnector-vector" && string(header.Value) == "p1-block" {
			status := t.engine.denyStatus
			if status == 0 {
				status = http.StatusForbidden
			}
			return processor.Decision{Action: processor.ActionDeny, Status: status}, nil
		}
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (t *snapshotP1Tx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	t.engine.bodyCalls++
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (*snapshotP1Tx) Close(context.Context, processor.Summary) {}

func TestForwardAuthNeverReturnsLeaseHeader(t *testing.T) {
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, processor.PassthroughEngine{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := []byte("hello")
	token, err := c.Reserve("uds-session", composite.ReservationSnapshot{Version: composite.ReservationSnapshotVersion, Protocol: "HTTP/1.1", ServerAddress: "127.0.0.1", ServerPort: 8080, Method: http.MethodPost, URI: "/check", Headers: []processor.Header{{Name: "host", Value: []byte("example.test")}}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/check", bytes.NewReader(body))
	req.Header.Add(LeaseHeader, token)
	req.Header.Add("X-Forwarded-Method", http.MethodPost)
	req.Header.Add("X-Forwarded-Uri", "/check")
	req.Header.Add("X-Forwarded-Proto", "http")
	req.Header.Add("X-Forwarded-Host", "example.test")
	req.Header.Add("X-Forwarded-For", "127.0.0.1")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182}))
	rec := httptest.NewRecorder()
	(&ForwardAuth{Coordinator: c}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(LeaseHeader); got != "" {
		t.Fatalf("sensitive response metadata leaked: lease=%q", got)
	}
}

func TestForwardAuthMissingLeaseFailsClosedBeforeEngineOpen(t *testing.T) {
	engine := &snapshotP1Engine{}
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/missing-lease", nil)
	rec := httptest.NewRecorder()
	(&ForwardAuth{Coordinator: c}).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if engine.openCalls != 0 {
		t.Fatalf("engine opened without a valid private lease: %d", engine.openCalls)
	}
}

func TestForwardAuthUsesOnlyPrivateReservationSnapshotForP1(t *testing.T) {
	engine := &snapshotP1Engine{}
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	token, err := c.Reserve("uds-session", composite.ReservationSnapshot{
		Version:  composite.ReservationSnapshotVersion,
		Protocol: "HTTP/1.1", ServerAddress: "127.0.0.1", ServerPort: 8080,
		Method: http.MethodPost,
		URI:    "/snapshot",
		Headers: []processor.Header{
			{Name: "host", Value: []byte("example.test")},
			{Name: "x-msconnector-vector", Value: []byte("p1-block")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/snapshot", bytes.NewBufferString("body"))
	req.Header.Set(LeaseHeader, token)
	req.Header.Set("X-Forwarded-Method", http.MethodPost)
	req.Header.Set("X-Forwarded-Uri", "/snapshot")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "example.test")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	// This request has no vector header. A deny proves P1 came exclusively
	// from the UDS-retained snapshot, not from the ForwardAuth HTTP allow-list.
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182}))
	rec := httptest.NewRecorder()
	(&ForwardAuth{Coordinator: c}).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if engine.bodyCalls != 0 {
		t.Fatalf("P2 ran after P1 terminal decision: %d", engine.bodyCalls)
	}
	if len(engine.headers) != 2 || engine.headers[1].Name != "x-msconnector-vector" || string(engine.headers[1].Value) != "p1-block" {
		t.Fatalf("P1 headers = %#v", engine.headers)
	}
}

func TestForwardAuthNormalizesInvalidRequestDenyStatus(t *testing.T) {
	for _, malformedStatus := range []int{http.StatusEarlyHints, http.StatusOK} {
		t.Run(http.StatusText(malformedStatus), func(t *testing.T) {
			engine := &snapshotP1Engine{denyStatus: malformedStatus}
			c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, engine, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			token, err := c.Reserve("uds-session", composite.ReservationSnapshot{
				Version:  composite.ReservationSnapshotVersion,
				Protocol: "HTTP/1.1", ServerAddress: "127.0.0.1", ServerPort: 8080,
				Method: http.MethodGet,
				URI:    "/invalid-deny",
				Headers: []processor.Header{
					{Name: "host", Value: []byte("example.test")},
					{Name: "x-msconnector-vector", Value: []byte("p1-block")},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := serveForwardAuthTestRequest(t, c, token, "/invalid-deny", "127.0.0.1"); got != http.StatusForbidden {
				t.Fatalf("invalid request deny status reached client: got %d, want %d", got, http.StatusForbidden)
			}
		})
	}
}

func TestForwardAuthRejectsNonIPAddressForwardedClient(t *testing.T) {
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, processor.PassthroughEngine{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	token, err := c.Reserve("uds-session", composite.ReservationSnapshot{Version: composite.ReservationSnapshotVersion, Protocol: "HTTP/1.1", ServerAddress: "127.0.0.1", ServerPort: 8080, Method: http.MethodGet, URI: "/", Headers: []processor.Header{{Name: "host", Value: []byte("example.test")}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := serveForwardAuthTestRequest(t, c, token, "/", "untrusted-client-name"); got != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", got)
	}
}

func serveForwardAuthTestRequest(t *testing.T, c *composite.Coordinator, token, uri, client string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+uri, nil)
	for name, value := range map[string]string{
		LeaseHeader:          token,
		"X-Forwarded-Method": http.MethodGet,
		"X-Forwarded-Uri":    uri,
		"X-Forwarded-Proto":  "http",
		"X-Forwarded-Host":   "example.test",
		"X-Forwarded-For":    client,
	} {
		req.Header.Set(name, value)
	}
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182}))
	rec := httptest.NewRecorder()
	(&ForwardAuth{Coordinator: c}).ServeHTTP(rec, req)
	return rec.Code
}
