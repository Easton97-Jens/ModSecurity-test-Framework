package compositeenvoy

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type recordingOpener struct {
	opened processor.StreamMetadata
	opens  int
	body   []byte
	eos    bool
}

func (o *recordingOpener) Open(_ context.Context, meta processor.StreamMetadata) (processor.Transaction, error) {
	o.opened = meta
	o.opens++
	return recordingTransaction{opener: o}, nil
}

type recordingTransaction struct{ opener *recordingOpener }

func (recordingTransaction) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (tx recordingTransaction) ProcessBody(_ context.Context, _ processor.Direction, body []byte, eos bool) (processor.Decision, error) {
	tx.opener.body = append(tx.opener.body, body...)
	tx.opener.eos = eos
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (recordingTransaction) Close(context.Context, processor.Summary) {}

func TestCheckUsesServerDecisionIDAndMetadataOnlyLease(t *testing.T) {
	opener := &recordingOpener{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Check(context.Background(), &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source:      &authv3.AttributeContext_Peer{Address: testAddress("127.0.0.1", 1234)},
		Destination: &authv3.AttributeContext_Peer{Address: testAddress("127.0.0.1", 8080)},
		Request:     &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Id: "client-id", Method: "POST", Path: "/", Host: "example.test", Protocol: "HTTP/1.1", Headers: map[string]string{"x-request-id": "client-id"}, RawBody: []byte("body")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetOkResponse() == nil || response.GetDynamicMetadata() == nil {
		t.Fatal("allow response omitted dynamic metadata")
	}
	if response.GetOkResponse().GetHeaders() != nil && len(response.GetOkResponse().GetHeaders()) != 0 {
		t.Fatal("lease was returned as an HTTP header")
	}
	if opener.opened.TransactionID == "" || opener.opened.TransactionID == "client-id" {
		t.Fatalf("decision ID was not server generated: %q", opener.opened.TransactionID)
	}
	if _, ok := response.GetDynamicMetadata().GetFields()["lease"]; !ok {
		t.Fatal("lease missing from dynamic metadata")
	}
	if _, ok := response.GetDynamicMetadata().GetFields()[metadataTerminal]; ok {
		t.Fatal("allow response was marked as a terminal local reply")
	}
}

func TestAuthRequestExcludesClientSuppliedCompositeLeaseHeader(t *testing.T) {
	request := authCheckRequest(nil)
	request.GetAttributes().GetRequest().GetHttp().Headers = map[string]string{
		"X-MsConnector-Composite-Lease": "client-spoof",
		"x-msconnector-composite-lease": "client-spoof-duplicate",
		"X-Request-ID":                  "request-id",
	}
	_, headers, _, err := authRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range headers {
		if header.Name == compositeLeaseHeader {
			t.Fatalf("client-supplied protected header reached Common: %+v", headers)
		}
	}
	if len(headers) != 1 || headers[0].Name != "x-request-id" {
		t.Fatalf("headers=%v, want only non-reserved request header", headers)
	}
}

func TestCheckAcceptsExactly32ByteBodyAndMintsLease(t *testing.T) {
	opener := &recordingOpener{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Check(context.Background(), authCheckRequest(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if response.GetOkResponse() == nil || response.GetDynamicMetadata().GetFields()["lease"].GetStringValue() == "" {
		t.Fatalf("exactly 32 bytes did not receive allow/lease metadata: %v", response)
	}
}

func TestCheckForwards33ByteBodyWithoutConnectorPolicy(t *testing.T) {
	opener := &recordingOpener{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Check(context.Background(), authCheckRequest(make([]byte, 33)))
	if err != nil {
		t.Fatal(err)
	}
	if response.GetOkResponse() == nil {
		t.Fatalf("33-byte body response=%v, want engine allow", response)
	}
}

func TestCheckRejectsIncompleteOrAmbiguousBodyBeforeAdmission(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		raw     []*corev3.HeaderValue
	}{
		{name: "partial", headers: map[string]string{authPartialBodyHeader: "true"}},
		{name: "mixed case partial", headers: map[string]string{"X-Envoy-Auth-Partial-Body": "true"}},
		{name: "malformed", headers: map[string]string{authPartialBodyHeader: "0"}},
		{name: "empty", headers: map[string]string{authPartialBodyHeader: ""}},
		{name: "whitespace", headers: map[string]string{authPartialBodyHeader: " false "}},
		{name: "combined values", headers: map[string]string{authPartialBodyHeader: "false,true"}},
		{name: "case duplicate", headers: map[string]string{authPartialBodyHeader: "false", "X-Envoy-Auth-Partial-Body": "false"}},
		{name: "raw partial", raw: []*corev3.HeaderValue{{Key: authPartialBodyHeader, RawValue: []byte("true")}}},
		{name: "raw duplicate", raw: []*corev3.HeaderValue{{Key: authPartialBodyHeader, Value: "false"}, {Key: "X-Envoy-Auth-Partial-Body", Value: "false"}}},
		{name: "encoding conflict", raw: []*corev3.HeaderValue{{Key: authPartialBodyHeader, Value: "false", RawValue: []byte("false")}}},
		{name: "cross map duplicate", headers: map[string]string{authPartialBodyHeader: "false"}, raw: []*corev3.HeaderValue{{Key: authPartialBodyHeader, Value: "false"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, size := range []int{1, 64} {
				opener := &recordingOpener{}
				coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 1}, opener, nil)
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewAuthzServer(coordinator)
				if err != nil {
					coordinator.Close()
					t.Fatal(err)
				}
				req := authCheckRequest(make([]byte, size))
				h := req.GetAttributes().GetRequest().GetHttp()
				h.Headers = tc.headers
				h.HeaderMap = &corev3.HeaderMap{Headers: tc.raw}
				response, err := server.Check(context.Background(), req)
				coordinator.Close()
				if status.Code(err) != codes.InvalidArgument || response != nil || opener.opens != 0 || opener.eos {
					t.Fatalf("Check(%s,size=%d) response=%v err=%v opens=%d eos=%v, want InvalidArgument before native open/EOS/lease", tc.name, size, response, err, opener.opens, opener.eos)
				}
			}
		})
	}
}

func TestCheckForwardsCompleteBodyBeyondHostFixtureBuffer(t *testing.T) {
	for _, marker := range []string{"absent", "false", "raw false"} {
		t.Run(marker, func(t *testing.T) {
			opener := &recordingOpener{}
			coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 1}, opener, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Close()
			server, err := NewAuthzServer(coordinator)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(strings.Repeat("a", 256) + "tail-marker")
			req := authCheckRequest(body)
			h := req.GetAttributes().GetRequest().GetHttp()
			if marker == "false" {
				h.Headers = map[string]string{"X-Envoy-Auth-Partial-Body": "false"}
			}
			if marker == "raw false" {
				h.HeaderMap = &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: "X-Envoy-Auth-Partial-Body", RawValue: []byte("false")}}}
			}
			response, err := server.Check(context.Background(), req)
			if err != nil || response.GetOkResponse() == nil || !opener.eos || string(opener.body) != string(body) {
				t.Fatalf("Check(complete,%s) response=%v err=%v body=%q eos=%v, want full body/allow/lease", marker, response, err, opener.body, opener.eos)
			}
		})
	}
}

func TestCompositeHostTemplateRequiresCompleteAuthorizationBody(t *testing.T) {
	path := filepath.Join("..", "..", "..", "config", "envoy-ext-authz-composite.yaml.in")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	template := string(data)
	if strings.Count(template, "allow_partial_message: false") != 1 || strings.Contains(template, "allow_partial_message: true") {
		t.Fatal("composite template must require complete host authorization samples")
	}
	if !strings.Contains(template, "max_request_bytes: 33") || strings.Contains(template, "service enforces the 32-byte") {
		t.Fatal("composite template must retain its explicit host admission buffer without claiming an Engine policy")
	}
	for _, attribute := range []string{"response_attributes:", "- response.code_details", "- response.code"} {
		if !strings.Contains(template, attribute) {
			t.Fatalf("composite template omitted protected host attribute %q", attribute)
		}
	}
}

func hostRequestBufferReply(endOfStream bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{extProcAttributeNamespace: {Fields: map[string]*structpb.Value{
			responseCodeAttribute:   structpb.NewNumberValue(413),
			responseDetailAttribute: structpb.NewStringValue(hostRequestBufferDetail),
		}}},
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{
			EndOfStream: endOfStream,
			Headers:     &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: envoyStatusHeader, Value: "413"}}},
		}},
	}
}

func hostReplyServer(t *testing.T) (*ExtProcServer, *recordingOpener, *eventObserver) {
	t.Helper()
	opener := &recordingOpener{}
	observer := &eventObserver{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 1}, opener, observer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Close)
	server, err := NewExtProcServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	return server, opener, observer
}

func TestHostRequestBufferReplyContinuesWithoutCommonTransaction(t *testing.T) {
	cases := []struct {
		name     string
		requests []*extprocv3.ProcessingRequest
	}{
		{name: "headers EOS", requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(true)}},
		{name: "body EOS", requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(false), {Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("Payload Too Large"), EndOfStream: true}}}}},
		{name: "trailers EOS", requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(false), {Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("Payload Too Large")}}}, {Request: &extprocv3.ProcessingRequest_ResponseTrailers{ResponseTrailers: &extprocv3.HttpTrailers{}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, opener, observer := hostReplyServer(t)
			stream := &processStream{requests: tc.requests}
			if err := server.Process(stream); err != nil {
				t.Fatal(err)
			}
			if len(stream.responses) != len(tc.requests) || opener.opens != 0 || opener.eos || len(observer.events) != 0 {
				t.Fatalf("Process(%s) responses=%v opens=%d eos=%v events=%v, want ordered continuation without Common", tc.name, stream.responses, opener.opens, opener.eos, observer.events)
			}
			for _, response := range stream.responses {
				if response.GetImmediateResponse() != nil {
					t.Fatalf("Process(%s) replaced host413: %v", tc.name, response)
				}
			}
		})
	}
}

func TestHostRequestBufferReplyRequiresProtectedExactProvenance(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*extprocv3.ProcessingRequest)
	}{
		{name: "missing attributes", mutate: func(r *extprocv3.ProcessingRequest) { r.Attributes = nil }},
		{name: "wrong namespace", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Attributes["client"] = r.Attributes[extProcAttributeNamespace]
			delete(r.Attributes, extProcAttributeNamespace)
		}},
		{name: "nil attributes", mutate: func(r *extprocv3.ProcessingRequest) { r.Attributes[extProcAttributeNamespace] = nil }},
		{name: "missing code", mutate: func(r *extprocv3.ProcessingRequest) {
			delete(r.Attributes[extProcAttributeNamespace].Fields, responseCodeAttribute)
		}},
		{name: "string code", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Attributes[extProcAttributeNamespace].Fields[responseCodeAttribute] = structpb.NewStringValue("413")
		}},
		{name: "fractional code", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Attributes[extProcAttributeNamespace].Fields[responseCodeAttribute] = structpb.NewNumberValue(413.5)
		}},
		{name: "missing detail", mutate: func(r *extprocv3.ProcessingRequest) {
			delete(r.Attributes[extProcAttributeNamespace].Fields, responseDetailAttribute)
		}},
		{name: "upstream detail", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Attributes[extProcAttributeNamespace].Fields[responseDetailAttribute] = structpb.NewStringValue("via_upstream")
		}},
		{name: "wrong detail type", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Attributes[extProcAttributeNamespace].Fields[responseDetailAttribute] = structpb.NewBoolValue(true)
		}},
		{name: "wrong status", mutate: func(r *extprocv3.ProcessingRequest) { r.GetResponseHeaders().Headers.Headers[0].Value = "403" }},
		{name: "noncanonical status", mutate: func(r *extprocv3.ProcessingRequest) { r.GetResponseHeaders().Headers.Headers[0].Value = "0413" }},
		{name: "duplicate status", mutate: func(r *extprocv3.ProcessingRequest) {
			r.GetResponseHeaders().Headers.Headers = append(r.GetResponseHeaders().Headers.Headers, &corev3.HeaderValue{Key: ":STATUS", Value: "413"})
		}},
		{name: "conflicting status encoding", mutate: func(r *extprocv3.ProcessingRequest) {
			r.GetResponseHeaders().Headers.Headers[0].RawValue = []byte("413")
		}},
		{name: "malformed header", mutate: func(r *extprocv3.ProcessingRequest) {
			r.GetResponseHeaders().Headers.Headers = append(r.GetResponseHeaders().Headers.Headers, nil)
		}},
		{name: "location", mutate: func(r *extprocv3.ProcessingRequest) {
			r.GetResponseHeaders().Headers.Headers = append(r.GetResponseHeaders().Headers.Headers, &corev3.HeaderValue{Key: "location", Value: "https://example.test"})
		}},
		{name: "empty authz namespace", mutate: func(r *extprocv3.ProcessingRequest) {
			r.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{metadataNamespace: nil}}
		}},
		{name: "typed authz namespace", mutate: func(r *extprocv3.ProcessingRequest) {
			r.MetadataContext = &corev3.Metadata{TypedFilterMetadata: map[string]*anypb.Any{metadataNamespace: {}}}
		}},
		{name: "invalid authz lease", mutate: func(r *extprocv3.ProcessingRequest) {
			r.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{metadataNamespace: {Fields: map[string]*structpb.Value{metadataLease: structpb.NewStringValue("fake"), metadataVersion: structpb.NewNumberValue(1)}}}}
		}},
		{name: "HTTP header spoof", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Attributes = nil
			r.GetResponseHeaders().Headers.Headers = append(r.GetResponseHeaders().Headers.Headers, &corev3.HeaderValue{Key: responseDetailAttribute, Value: hostRequestBufferDetail}, &corev3.HeaderValue{Key: responseCodeAttribute, Value: "413"})
		}},
		{name: "deprecated attributes spoof", mutate: func(r *extprocv3.ProcessingRequest) {
			r.GetResponseHeaders().Attributes = r.Attributes
			r.Attributes = nil
		}},
		{name: "request header phase", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Request = &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}}}
		}},
		{name: "body before header", mutate: func(r *extprocv3.ProcessingRequest) {
			r.Request = &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{EndOfStream: true}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, opener, observer := hostReplyServer(t)
			r := hostRequestBufferReply(true)
			tc.mutate(r)
			stream := &processStream{requests: []*extprocv3.ProcessingRequest{r}}
			if err := server.Process(stream); err != nil {
				t.Fatal(err)
			}
			if len(stream.responses) != 1 || stream.responses[0].GetImmediateResponse().GetStatus().GetCode() != 503 || opener.opens != 0 || opener.eos || len(observer.events) != 0 {
				t.Fatalf("Process(%s) responses=%v opens=%d eos=%v events=%v, want503 with no Common admission", tc.name, stream.responses, opener.opens, opener.eos, observer.events)
			}
		})
	}
}

func TestHostRequestBufferReplyKeepsStreamOrderAndIOErrors(t *testing.T) {
	server, opener, observer := hostReplyServer(t)
	for _, next := range []*extprocv3.ProcessingRequest{hostRequestBufferReply(false), {Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{}}}} {
		stream := &processStream{requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(false), next}}
		if err := server.Process(stream); err != nil {
			t.Fatal(err)
		}
		if len(stream.responses) != 2 || stream.responses[1].GetImmediateResponse().GetStatus().GetCode() != 503 {
			t.Fatalf("Process(out-of-order)=%v, want503", stream.responses)
		}
	}
	writeErr := errors.New("host continuation write failed")
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(true)}, sendErr: writeErr}
	if err := server.Process(stream); !errors.Is(err, writeErr) {
		t.Fatalf("Process(write failure)=%v, want%v", err, writeErr)
	}
	stream = &processStream{requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(false)}, recvErr: context.Canceled}
	if err := server.Process(stream); err != nil {
		t.Fatalf("Process(read canceled)=%v, want clean cancellation", err)
	}
	stream = &processStream{requests: []*extprocv3.ProcessingRequest{hostRequestBufferReply(false)}, recvErr: errors.New("host continuation read failed")}
	if err := server.Process(stream); status.Code(err) != codes.Unavailable {
		t.Fatalf("Process(read failure)=%v, wantUnavailable", err)
	}
	if opener.opens != 0 || opener.eos || len(observer.events) != 0 {
		t.Fatalf("Common touched after host IO/order errors: %+v events=%v", opener, observer.events)
	}
}

// strictRequestOpener models the Common runtime's transport-result allowlist.
// It prevents the Envoy adapter tests from accepting connector-local labels
// that make a real CGo/Common host fail closed with a 503.
type strictRequestOpener struct {
	headerAction           processor.Action
	bodyAction             processor.Action
	status                 int
	redirectURL            string
	rejectNativeHostAction bool
	tx                     *strictRequestTransaction
}

func (o *strictRequestOpener) Open(_ context.Context, _ processor.StreamMetadata) (processor.Transaction, error) {
	o.tx = &strictRequestTransaction{headerAction: o.headerAction, bodyAction: o.bodyAction, status: o.status, redirectURL: o.redirectURL, rejectNativeHostAction: o.rejectNativeHostAction}
	return o.tx, nil
}

type strictRequestTransaction struct {
	headerAction           processor.Action
	bodyAction             processor.Action
	status                 int
	redirectURL            string
	rejectNativeHostAction bool
	actions                []processor.HostAction
}

func (t *strictRequestTransaction) ProcessHeaders(_ context.Context, _ processor.Direction, _ []processor.Header, _ bool) (processor.Decision, error) {
	return processor.Decision{Action: t.headerAction, Status: t.status, RedirectURL: t.redirectURL}, nil
}
func (t *strictRequestTransaction) ProcessBody(_ context.Context, _ processor.Direction, _ []byte, _ bool) (processor.Decision, error) {
	return processor.Decision{Action: t.bodyAction, Status: t.status, RedirectURL: t.redirectURL}, nil
}
func (t *strictRequestTransaction) Close(context.Context, processor.Summary) {}
func (t *strictRequestTransaction) RecordHostAction(_ context.Context, action processor.HostAction) error {
	if t.rejectNativeHostAction {
		return errors.New("synthetic request body limit invoked native Common host action")
	}
	if action.TransportResult != commonTransportHTTPStatus {
		return errors.New("noncanonical Common transport result")
	}
	t.actions = append(t.actions, action)
	return nil
}

type canonicalTransportCase struct {
	name             string
	headerAction     processor.Action
	bodyAction       processor.Action
	body             []byte
	wantStatus       int32
	wantNativeAction bool
}

func TestCheckUsesCanonicalCommonTransportForDenyAndBodyLimit(t *testing.T) {
	tests := []canonicalTransportCase{
		{name: "p1 deny", headerAction: processor.ActionDeny, bodyAction: processor.ActionAllow, wantStatus: 403, wantNativeAction: true},
		{name: "p2 deny", headerAction: processor.ActionAllow, bodyAction: processor.ActionDeny, body: []byte("p2"), wantStatus: 403, wantNativeAction: true},
		{name: "p2 native body reject", headerAction: processor.ActionAllow, bodyAction: processor.ActionDeny, body: make([]byte, 33), wantStatus: 403, wantNativeAction: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runCanonicalTransportCase(t, test) })
	}
}

func runCanonicalTransportCase(t *testing.T, test canonicalTransportCase) {
	t.Helper()
	opener := &strictRequestOpener{headerAction: test.headerAction, bodyAction: test.bodyAction, status: 403, rejectNativeHostAction: !test.wantNativeAction}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Close)
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Check(context.Background(), authCheckRequest(test.body))
	if err != nil {
		t.Fatal(err)
	}
	if response.GetDeniedResponse() == nil || int32(response.GetDeniedResponse().GetStatus().GetCode()) != test.wantStatus {
		t.Fatalf("response=%v, want denied status %d", response, test.wantStatus)
	}
	if response.GetDynamicMetadata().GetFields()[metadataTerminal].GetStringValue() != metadataTerminalBlock || response.GetDynamicMetadata().GetFields()[metadataLease] != nil {
		t.Fatalf("denied response did not carry only the protected terminal marker: %v", response.GetDynamicMetadata())
	}
	if opener.tx == nil {
		t.Fatal("missing request transaction")
	}
	if test.wantNativeAction && (len(opener.tx.actions) != 1 || opener.tx.actions[0].TransportResult != commonTransportHTTPStatus) {
		t.Fatalf("actions=%v, want one canonical %q action", opener.tx.actions, commonTransportHTTPStatus)
	}
	if !test.wantNativeAction && len(opener.tx.actions) != 0 {
		t.Fatalf("synthetic P2 limit invoked native Common action: %v", opener.tx.actions)
	}
}

func TestCheckNormalizesMalformedRequestDenyStatus(t *testing.T) {
	for _, malformedStatus := range []int{103, 200, 600} {
		t.Run(strconv.Itoa(malformedStatus), func(t *testing.T) {
			opener := &strictRequestOpener{headerAction: processor.ActionDeny, bodyAction: processor.ActionAllow, status: malformedStatus}
			response := runStrictCheck(t, opener)
			if got := int(response.GetDeniedResponse().GetStatus().GetCode()); got != 403 {
				t.Fatalf("visible status=%d, want 403", got)
			}
			if opener.tx == nil || len(opener.tx.actions) != 1 || opener.tx.actions[0].VisibleStatus != 403 || opener.tx.actions[0].Action != processor.AppliedActionDeny {
				t.Fatalf("host actions=%v, want one deny status 403", opener.tx.actions)
			}
		})
	}
}

func TestCheckPreservesValidatedRedirect(t *testing.T) {
	const location = "https://redirect.example.test/next"
	opener := &strictRequestOpener{headerAction: processor.ActionRedirect, bodyAction: processor.ActionAllow, status: 307, redirectURL: location}
	response := runStrictCheck(t, opener)
	denied := response.GetDeniedResponse()
	if denied == nil || int(denied.GetStatus().GetCode()) != 307 {
		t.Fatalf("response=%v, want redirect status 307", response)
	}
	foundLocation := false
	for _, header := range denied.GetHeaders() {
		if header.GetHeader().GetKey() == "location" && string(header.GetHeader().GetRawValue()) == location && header.GetHeader().GetValue() == "" && header.GetAppendAction() == corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			foundLocation = true
		}
	}
	if !foundLocation {
		t.Fatalf("redirect response omitted location %q: %v", location, denied)
	}
	if opener.tx == nil || len(opener.tx.actions) != 1 || opener.tx.actions[0].Action != processor.AppliedActionRedirect || opener.tx.actions[0].VisibleStatus != 307 {
		t.Fatalf("host actions=%v, want one redirect status 307", opener.tx.actions)
	}
}

func runStrictCheck(t *testing.T, opener *strictRequestOpener) *authv3.CheckResponse {
	t.Helper()
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Close)
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Check(context.Background(), authCheckRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestNormalizePolicyDecisionRejectsInvalidRedirect(t *testing.T) {
	got := normalizePolicyDecision(processor.Decision{Action: processor.ActionRedirect, Status: 307, RedirectURL: " \t"}, nil)
	if got.Action != processor.ActionDeny || got.Status != 403 || got.RedirectURL != "" {
		t.Fatalf("normalized invalid redirect=%#v, want deny 403", got)
	}
}

func TestNormalizePolicyDecisionRejectsUnsafeRedirectTarget(t *testing.T) {
	for _, target := range []string{"https://redirect.example.test/next\r\nX-Injected: true", strings.Repeat("a", 2049)} {
		got := normalizePolicyDecision(processor.Decision{Action: processor.ActionRedirect, Status: 307, RedirectURL: target}, nil)
		if got.Action != processor.ActionDeny || got.Status != 403 || got.RedirectURL != "" {
			t.Fatalf("normalized unsafe redirect=%#v, want deny 403", got)
		}
	}
}

func authCheckRequest(body []byte) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source:      &authv3.AttributeContext_Peer{Address: testAddress("127.0.0.1", 1234)},
		Destination: &authv3.AttributeContext_Peer{Address: testAddress("127.0.0.1", 8080)},
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: "POST", Path: "/", Host: "example.test", Protocol: "HTTP/1.1", RawBody: body,
		}},
	}}
}

func TestLeaseMetadataRequiresExactNamespaceAndVersion(t *testing.T) {
	lease := "server-lease"
	good, err := structpb.NewStruct(map[string]interface{}{"lease": lease, "version": float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	metadata := &coreMetadata{filter: map[string]*structpb.Struct{metadataNamespace: good}}
	if got, ok := leaseFromMetadata(metadata.toProto()); !ok || got != lease {
		t.Fatalf("valid metadata rejected: %q %v", got, ok)
	}
	wrong, _ := structpb.NewStruct(map[string]interface{}{"lease": lease, "version": float64(2)})
	metadata.filter[metadataNamespace] = wrong
	if _, ok := leaseFromMetadata(metadata.toProto()); ok {
		t.Fatal("wrong metadata version accepted")
	}
	metadata.filter = map[string]*structpb.Struct{"other.namespace": good}
	if _, ok := leaseFromMetadata(metadata.toProto()); ok {
		t.Fatal("lease from unexpected namespace accepted")
	}
}

// coreMetadata keeps this test's construction readable without leaking Envoy
// metadata details into the coordinator package.
type coreMetadata struct{ filter map[string]*structpb.Struct }

func (m *coreMetadata) toProto() *corev3.Metadata { return &corev3.Metadata{FilterMetadata: m.filter} }

func testAddress(host string, port uint32) *corev3.Address {
	return &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{Address: host, PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port}}}}
}

type processStream struct {
	requests  []*extprocv3.ProcessingRequest
	responses []*extprocv3.ProcessingResponse
	sendErr   error
	recvErr   error
}

func (s *processStream) SetHeader(metadata.MD) error  { return nil }
func (s *processStream) SendHeader(metadata.MD) error { return nil }
func (s *processStream) SetTrailer(metadata.MD)       {}
func (s *processStream) Context() context.Context     { return context.Background() }
func (s *processStream) SendMsg(interface{}) error    { return nil }
func (s *processStream) RecvMsg(interface{}) error    { return nil }
func (s *processStream) Send(response *extprocv3.ProcessingResponse) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.responses = append(s.responses, response)
	return nil
}
func (s *processStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(s.requests) == 0 {
		if s.recvErr != nil {
			return nil, s.recvErr
		}
		return nil, io.EOF
	}
	request := s.requests[0]
	s.requests = s.requests[1:]
	return request, nil
}

type eventObserver struct {
	events []composite.Event
	notify chan composite.Event
}

func (o *eventObserver) Observe(event composite.Event) error {
	o.events = append(o.events, event)
	if o.notify != nil {
		select {
		case o.notify <- event:
		default:
		}
	}
	return nil
}

type responseOpener struct {
	action        processor.Action
	bodyAction    processor.Action
	status        int
	commitErr     error
	hostActionErr error
	bodyErr       error
	tx            *responseTransaction
}

func (o *responseOpener) Open(_ context.Context, _ processor.StreamMetadata) (processor.Transaction, error) {
	o.tx = &responseTransaction{action: o.action, bodyAction: o.bodyAction, status: o.status, commitErr: o.commitErr, hostActionErr: o.hostActionErr, bodyErr: o.bodyErr}
	return o.tx, nil
}

type responseTransaction struct {
	action            processor.Action
	bodyAction        processor.Action
	bodyActions       []processor.Action
	status            int
	actions           []processor.HostAction
	commits           int
	commitErr         error
	hostActionErr     error
	bodyErr           error
	expectedTransport string
}

func (t *responseTransaction) ProcessHeaders(_ context.Context, direction processor.Direction, _ []processor.Header, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionResponse {
		return processor.Decision{Action: t.action, Status: t.status}, nil
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (t *responseTransaction) ProcessBody(_ context.Context, direction processor.Direction, _ []byte, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionResponse {
		if t.bodyErr != nil {
			return processor.Decision{}, t.bodyErr
		}
		action := t.bodyAction
		if len(t.bodyActions) != 0 {
			action = t.bodyActions[0]
			t.bodyActions = t.bodyActions[1:]
		}
		return processor.Decision{Action: action, Status: t.status}, nil
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func TestProcessP4ProcessingErrorDoesNotSendSecondImmediateResponse(t *testing.T) {
	server, opener, _, lease := newProcessFixture(t, processor.ActionAllow, 200)
	// Configure the transaction before ext_proc claims it; the fixture opener
	// copies this fault into the transaction at Open time.
	opener.tx.bodyErr = errors.New("body inspection failed")
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialRequest(lease),
		{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}}}}},
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("body"), EndOfStream: true}}},
	}}
	if err := server.Process(stream); err == nil {
		t.Fatal("post-commit body error unexpectedly succeeded")
	}
	if len(stream.responses) != 2 || stream.responses[1].GetResponseHeaders() == nil {
		t.Fatalf("responses=%v, want only the committed P3 CONTINUE", stream.responses)
	}
}
func (t *responseTransaction) Close(context.Context, processor.Summary) {}
func (t *responseTransaction) RecordHostAction(_ context.Context, action processor.HostAction) error {
	if t.hostActionErr != nil {
		return t.hostActionErr
	}
	if t.expectedTransport != "" && action.TransportResult != t.expectedTransport {
		return errors.New("noncanonical Common transport result")
	}
	t.actions = append(t.actions, action)
	return nil
}
func (t *responseTransaction) MarkResponseCommitted(context.Context) error {
	t.commits++
	return t.commitErr
}

func newProcessFixture(t *testing.T, action processor.Action, statusCode int) (*ExtProcServer, *responseOpener, *eventObserver, string) {
	return newProcessFixtureWithActions(t, action, action, statusCode)
}

func newProcessFixtureWithActions(t *testing.T, headerAction, bodyAction processor.Action, statusCode int) (*ExtProcServer, *responseOpener, *eventObserver, string) {
	return newProcessFixtureWithFailures(t, headerAction, bodyAction, statusCode, nil, nil)
}

func newProcessFixtureWithFailures(t *testing.T, headerAction, bodyAction processor.Action, statusCode int, commitErr, hostActionErr error) (*ExtProcServer, *responseOpener, *eventObserver, string) {
	t.Helper()
	opener := &responseOpener{action: headerAction, bodyAction: bodyAction, status: statusCode, commitErr: commitErr, hostActionErr: hostActionErr}
	observer := &eventObserver{notify: make(chan composite.Event, 64)}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, observer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Close)
	authz, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	check, err := authz.Check(context.Background(), &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Source: &authv3.AttributeContext_Peer{Address: testAddress("127.0.0.1", 1234)}, Destination: &authv3.AttributeContext_Peer{Address: testAddress("127.0.0.1", 8080)}, Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: "/", Host: "example.test", Protocol: "HTTP/1.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	lease, ok := check.GetDynamicMetadata().GetFields()["lease"]
	if !ok {
		t.Fatal("fixture did not receive lease")
	}
	returnServer, err := NewExtProcServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	return returnServer, opener, observer, lease.GetStringValue()
}

func processRequest(lease string, request *extprocv3.ProcessingRequest) *extprocv3.ProcessingRequest {
	request.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{metadataNamespace: {Fields: map[string]*structpb.Value{"lease": structpb.NewStringValue(lease), "version": structpb.NewNumberValue(1)}}}}
	return request
}

func initialRequest(lease string) *extprocv3.ProcessingRequest {
	return processRequest(lease, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{}}})
}

func initialResponseHeaders(lease string, status string, endOfStream bool) *extprocv3.ProcessingRequest {
	return processRequest(lease, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{EndOfStream: endOfStream, Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: status}}}}}})
}

func terminalResponseHeaders(status string, endOfStream bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{metadataNamespace: terminalBlockMetadata()}}, Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{EndOfStream: endOfStream, Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: status}}}}}}
}

func TestProcessMissingMetadataFailsClosed503(t *testing.T) {
	server, _, _, _ := newProcessFixture(t, processor.ActionAllow, 200)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{EndOfStream: true, Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "403"}}}}}}}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetImmediateResponse().GetStatus().GetCode() != 503 {
		t.Fatalf("responses=%v, want one 503 immediate response", stream.responses)
	}
}

func TestProcessMarkedTerminalLocalReplyContinuesWithoutClaim(t *testing.T) {
	opener := &responseOpener{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Close)
	server, err := NewExtProcServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{terminalResponseHeaders("413", true)}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetResponseHeaders() == nil {
		t.Fatalf("responses=%v, want one terminal response-header CONTINUE", stream.responses)
	}
	if opener.tx != nil {
		t.Fatal("marked terminal local reply opened or claimed a Common transaction")
	}
}

func TestProcessP3DenyImmediateAndAction(t *testing.T) {
	server, opener, _, lease := newProcessFixture(t, processor.ActionDeny, 451)
	opener.tx.expectedTransport = commonTransportHTTPStatus
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{initialRequest(lease), {Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}}}}}}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 2 || stream.responses[1].GetImmediateResponse() == nil {
		t.Fatalf("responses=%v, want P3 immediate response", stream.responses)
	}
	if got := int(stream.responses[1].GetImmediateResponse().GetStatus().GetCode()); got != 451 {
		t.Fatalf("P3 visible status=%d, want 451", got)
	}
	if len(opener.tx.actions) != 1 || opener.tx.actions[0].Action != processor.AppliedActionDeny || opener.tx.actions[0].VisibleStatus != 451 || opener.tx.actions[0].TransportResult != commonTransportHTTPStatus {
		t.Fatalf("actions=%v, want deny", opener.tx.actions)
	}
}

func TestProcessMarkedTerminalRedirectPassesThrough(t *testing.T) {
	const location = "https://redirect.example.test/next"
	opener := &strictRequestOpener{headerAction: processor.ActionRedirect, bodyAction: processor.ActionAllow, status: 307, redirectURL: location}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Close)
	authz, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := authz.Check(context.Background(), authCheckRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	if terminal.GetDeniedResponse() == nil || int(terminal.GetDeniedResponse().GetStatus().GetCode()) != 307 {
		t.Fatalf("terminal response=%v, want redirect 307", terminal)
	}
	requestTransaction := opener.tx
	server, err := NewExtProcServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{{
		MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{metadataNamespace: terminal.GetDynamicMetadata()}},
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{
			EndOfStream: true,
			Headers:     &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "307"}, {Key: "location", Value: location}}},
		}},
	}}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetResponseHeaders() == nil || stream.responses[0].GetImmediateResponse() != nil {
		t.Fatalf("responses=%v, want terminal redirect continuation", stream.responses)
	}
	if opener.tx != requestTransaction {
		t.Fatal("marked terminal redirect opened a second transaction")
	}
}

func TestProcessMarkedTerminalServerErrorPassesThrough(t *testing.T) {
	server, opener, _, _ := newProcessFixture(t, processor.ActionAllow, 200)
	requestTransaction := opener.tx
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{terminalResponseHeaders("500", true)}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetResponseHeaders() == nil || stream.responses[0].GetImmediateResponse() != nil {
		t.Fatalf("responses=%v, want terminal 500 continuation", stream.responses)
	}
	if opener.tx != requestTransaction {
		t.Fatal("marked terminal 500 opened a second Common transaction")
	}
}

func TestProcessMarkedTerminalInvalidRedirectFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		headers []*corev3.HeaderValue
	}{
		{name: "missing location", headers: []*corev3.HeaderValue{{Key: ":status", Value: "307"}}},
		{name: "duplicate location", headers: []*corev3.HeaderValue{{Key: ":status", Value: "307"}, {Key: "location", Value: "https://redirect.example.test/a"}, {Key: "location", Value: "https://redirect.example.test/b"}}},
		{name: "newline location", headers: []*corev3.HeaderValue{{Key: ":status", Value: "307"}, {Key: "location", Value: "https://redirect.example.test/next\r\nX-Injected: true"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opener := &responseOpener{}
			coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(coordinator.Close)
			server, err := NewExtProcServer(coordinator)
			if err != nil {
				t.Fatal(err)
			}
			stream := &processStream{requests: []*extprocv3.ProcessingRequest{{
				MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{metadataNamespace: terminalBlockMetadata()}},
				Request:         &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{EndOfStream: true, Headers: &corev3.HeaderMap{Headers: test.headers}}},
			}}}
			if err := server.Process(stream); err != nil {
				t.Fatal(err)
			}
			if len(stream.responses) != 1 || stream.responses[0].GetImmediateResponse() == nil || int(stream.responses[0].GetImmediateResponse().GetStatus().GetCode()) != 503 {
				t.Fatalf("responses=%v, want one fail-closed 503", stream.responses)
			}
			if opener.tx != nil {
				t.Fatal("invalid marked redirect opened a Common transaction")
			}
		})
	}
}

func TestProcessNormalizesMalformedP3DenyStatus(t *testing.T) {
	for _, malformedStatus := range []int{103, 200, 600} {
		t.Run(strconv.Itoa(malformedStatus), func(t *testing.T) {
			server, opener, _, lease := newProcessFixture(t, processor.ActionDeny, malformedStatus)
			opener.tx.expectedTransport = commonTransportHTTPStatus
			stream := &processStream{requests: []*extprocv3.ProcessingRequest{
				initialRequest(lease),
				{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}}}}},
			}}
			if err := server.Process(stream); err != nil {
				t.Fatal(err)
			}
			if len(stream.responses) != 2 || stream.responses[1].GetImmediateResponse() == nil || int(stream.responses[1].GetImmediateResponse().GetStatus().GetCode()) != 403 {
				t.Fatalf("responses=%v, want P3 immediate status 403", stream.responses)
			}
			if len(opener.tx.actions) != 1 || opener.tx.actions[0].Action != processor.AppliedActionDeny || opener.tx.actions[0].VisibleStatus != 403 || opener.tx.actions[0].TransportResult != commonTransportHTTPStatus {
				t.Fatalf("host actions=%v, want one deny status 403", opener.tx.actions)
			}
		})
	}
}

func TestSendImmediatePreservesValidatedRedirect(t *testing.T) {
	stream := &processStream{}
	if err := sendImmediate(stream, processor.Decision{Action: processor.ActionRedirect, Status: 307, RedirectURL: "https://redirect.example.test/next"}); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetImmediateResponse() == nil {
		t.Fatalf("responses=%v, want one redirect immediate response", stream.responses)
	}
	immediate := stream.responses[0].GetImmediateResponse()
	if got := int(immediate.GetStatus().GetCode()); got != 307 {
		t.Fatalf("redirect status=%d, want 307", got)
	}
	headers := immediate.GetHeaders().GetSetHeaders()
	if len(headers) != 1 || headers[0].GetHeader().GetKey() != "location" || string(headers[0].GetHeader().GetRawValue()) != "https://redirect.example.test/next" || headers[0].GetHeader().GetValue() != "" || headers[0].GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Fatalf("redirect headers=%v, want one location", headers)
	}
}

func TestProcessP4DisruptiveContinuesLogOnly(t *testing.T) {
	server, opener, _, lease := newProcessFixtureWithActions(t, processor.ActionAllow, processor.ActionDeny, 451)
	opener.tx.expectedTransport = commonTransportLogOnly
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{initialRequest(lease), {Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "204"}}}}}}, {Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("body"), EndOfStream: true}}}}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 3 || stream.responses[2].GetImmediateResponse() != nil {
		t.Fatalf("responses=%v, want P4 CONTINUE", stream.responses)
	}
	if len(opener.tx.actions) != 1 || opener.tx.actions[0].Action != processor.AppliedActionLogOnly || opener.tx.actions[0].VisibleStatus != 204 || opener.tx.actions[0].TransportResult != commonTransportLogOnly {
		t.Fatalf("actions=%v, want status 204 log_only", opener.tx.actions)
	}
}

func TestProcessStreamedP4DenyEmitsOnceAndSuppressesNeutralAllow(t *testing.T) {
	server, opener, observer, lease := newProcessFixtureWithActions(t, processor.ActionAllow, processor.ActionAllow, 451)
	opener.tx.bodyActions = []processor.Action{processor.ActionDeny, processor.ActionAllow}
	opener.tx.expectedTransport = commonTransportLogOnly
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialRequest(lease),
		{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}}}}},
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("first"), EndOfStream: false}}},
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{EndOfStream: true}}},
	}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(opener.tx.actions) != 1 || opener.tx.actions[0].Action != processor.AppliedActionLogOnly {
		t.Fatalf("actions=%v, want one P4 log_only action", opener.tx.actions)
	}
	p4, neutral := eventCountsUntilTerminal(t, observer)
	if p4 != 1 || neutral != 0 {
		t.Fatalf("P4=%d neutral=%d, want one P4 and no neutral allow after log_only", p4, neutral)
	}
}

func TestProcessStreamedP4AllowEmitsAtEOSAndRecordsNeutralAllow(t *testing.T) {
	server, _, observer, lease := newProcessFixtureWithActions(t, processor.ActionAllow, processor.ActionAllow, 200)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialRequest(lease),
		{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}}}}},
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("first"), EndOfStream: false}}},
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{EndOfStream: true}}},
	}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	p4, neutral := eventCountsUntilTerminal(t, observer)
	if p4 != 1 || neutral != 1 {
		t.Fatalf("P4=%d neutral=%d, want one P4 and one neutral allow", p4, neutral)
	}
}

func eventCountsUntilTerminal(t *testing.T, observer *eventObserver) (int, int) {
	t.Helper()
	p4, neutral := 0, 0
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case event := <-observer.notify:
			switch event.Phase {
			case "P4":
				p4++
			case "neutral_outcome":
				if event.ActualHostAction == "allow" {
					neutral++
				}
			case "terminal":
				return p4, neutral
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for terminal composite event")
		}
	}
}

func TestProcessHeaderOnlyAllowNeutralOutcome(t *testing.T) {
	server, opener, observer, lease := newProcessFixture(t, processor.ActionAllow, 200)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{initialResponseHeaders(lease, "201", true)}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetResponseHeaders() == nil {
		t.Fatalf("responses=%v, want header CONTINUE", stream.responses)
	}
	found := false
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for !found {
		select {
		case event := <-observer.notify:
			if event.Phase == "neutral_outcome" && event.ActualHostAction == "allow" {
				found = true
			}
		case <-deadline.C:
			t.Fatalf("events=%v, want neutral allow", observer.events)
		}
	}
	if !found {
		t.Fatalf("events=%v, want neutral allow", observer.events)
	}
	if opener.tx == nil {
		t.Fatal("transaction missing")
	}
}

func TestProcessHeaderOnlyDenyEmitsFinalP4BeforeTerminalization(t *testing.T) {
	server, _, observer, lease := newProcessFixture(t, processor.ActionDeny, 451)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{initialRequest(lease), initialResponseHeaders(lease, "200", true)}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	p4, neutral := eventCountsUntilTerminal(t, observer)
	if p4 != 1 || neutral != 0 {
		t.Fatalf("P4=%d neutral=%d, want final disruptive P4 and no neutral allow", p4, neutral)
	}
}

func TestProcessOutOfOrderResponseFailsClosed(t *testing.T) {
	server, _, _, lease := newProcessFixture(t, processor.ActionAllow, 200)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{initialRequest(lease), {Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{EndOfStream: true}}}}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 2 || stream.responses[1].GetImmediateResponse().GetStatus().GetCode() != 503 {
		t.Fatalf("responses=%v, want out-of-order 503", stream.responses)
	}
}

func TestProcessP3ImmediateRecorderFailureLeavesOutcomeUnknown(t *testing.T) {
	server, opener, _, lease := newProcessFixtureWithFailures(t, processor.ActionDeny, processor.ActionDeny, 451, nil, errors.New("recorder failed"))
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialRequest(lease),
		{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}}}}},
	}}
	if err := server.Process(stream); err == nil {
		t.Fatal("P3 recorder failure unexpectedly succeeded")
	}
	if len(stream.responses) != 2 || stream.responses[1].GetImmediateResponse() == nil {
		t.Fatalf("responses=%v, want only the already-sent P3 ImmediateResponse", stream.responses)
	}
	if len(opener.tx.actions) != 0 {
		t.Fatalf("actions=%v, must not claim an action after recorder failure", opener.tx.actions)
	}
}

func TestProcessP3AllowCommitFailureDoesNotSendSecondDecision(t *testing.T) {
	server, opener, _, lease := newProcessFixtureWithFailures(t, processor.ActionAllow, processor.ActionAllow, 200, errors.New("commit recorder failed"), nil)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialRequest(lease),
		{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "204"}}}}}},
	}}
	if err := server.Process(stream); err == nil {
		t.Fatal("P3 commit failure unexpectedly succeeded")
	}
	if len(stream.responses) != 2 || stream.responses[1].GetResponseHeaders() == nil || stream.responses[1].GetImmediateResponse() != nil {
		t.Fatalf("responses=%v, want only the already-sent P3 CONTINUE", stream.responses)
	}
	if opener.tx.commits != 1 {
		t.Fatalf("commit attempts=%d, want 1", opener.tx.commits)
	}
}
