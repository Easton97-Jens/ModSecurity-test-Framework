package native_middleware

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func fuzzUDSFrame(f *testing.F, opcode byte, payload []byte) []byte {
	f.Helper()
	var frame bytes.Buffer
	if err := writeUDSTestFrame(&frame, opcode, payload); err != nil {
		f.Fatalf("writeUDSTestFrame() error = %v", err)
	}
	return frame.Bytes()
}

func fuzzUDSResult(command, action byte, status uint16, transactionID, ruleID, redirect string) []byte {
	payload := make([]byte, 14+len(transactionID)+len(ruleID)+len(redirect))
	payload[0] = command
	payload[1] = udsResultOK
	payload[2] = action
	binary.BigEndian.PutUint16(payload[4:6], status)
	binary.BigEndian.PutUint16(payload[8:10], uint16(len(transactionID)))
	binary.BigEndian.PutUint16(payload[10:12], uint16(len(ruleID)))
	binary.BigEndian.PutUint16(payload[12:14], uint16(len(redirect)))
	offset := 14
	offset += copy(payload[offset:], transactionID)
	offset += copy(payload[offset:], ruleID)
	copy(payload[offset:], redirect)
	return payload
}

func FuzzUDSFrameAndResult(f *testing.F) {
	f.Add([]byte(nil), udsOpcodeBegin)
	f.Add([]byte("MSE1"), udsOpcodeBegin)
	f.Add(fuzzUDSFrame(f, udsOpcodeBegin, []byte("begin")), udsOpcodeBegin)
	f.Add(
		append(
			fuzzUDSFrame(f, udsOpcodeBegin, []byte("begin")),
			fuzzUDSFrame(f, udsOpcodeBegin, []byte("next"))...,
		),
		udsOpcodeBegin,
	)
	f.Add(
		fuzzUDSFrame(f, udsOpcodeResult, fuzzUDSResult(udsOpcodeBegin, udsActionAllow, 200, "", "", "")),
		udsOpcodeBegin,
	)
	f.Add(
		fuzzUDSFrame(
			f,
			udsOpcodeResult,
			fuzzUDSResult(udsOpcodeResponseHead, udsActionDeny, 403, "transaction", "rule-123", ""),
		),
		udsOpcodeResponseHead,
	)
	f.Add(
		fuzzUDSFrame(
			f,
			udsOpcodeResult,
			fuzzUDSResult(udsOpcodeResponseHead, udsActionRedirect, 302, "transaction", "rule-456", "https://example.test/next"),
		),
		udsOpcodeResponseHead,
	)

	f.Fuzz(func(t *testing.T, frame []byte, command byte) {
		if len(frame) > udsFrameHeaderSize+udsMaxPayload {
			return
		}
		reader := bytes.NewReader(frame)
		opcode, payload, err := readUDSFrame(reader)
		if err != nil {
			return
		}

		var roundTrip bytes.Buffer
		if err := writeUDSTestFrame(&roundTrip, opcode, payload); err != nil {
			t.Fatalf("writeUDSTestFrame() after read = %v", err)
		}
		consumed := frame[:len(frame)-reader.Len()]
		if !bytes.Equal(roundTrip.Bytes(), consumed) {
			t.Fatalf("frame round trip changed parsed frame")
		}
		if opcode != udsOpcodeResult {
			return
		}

		result, err := parseUDSResult(payload, command)
		if err != nil {
			return
		}
		if result.action > udsActionRedirect {
			t.Fatalf("accepted unsupported action %d", result.action)
		}
	})
}
