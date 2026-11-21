package agentid

import "testing"

func FuzzCanonicalJSONDeterminism(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":"x"}`))
	f.Add([]byte(`[1,2,{"c":null}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := DecodeJSON(data)
		if err != nil {
			return
		}
		first, err := CanonicalJSON(value)
		if err != nil {
			return
		}
		reparsed, err := DecodeJSON(first)
		if err != nil {
			t.Fatalf("canonical output is not valid JSON: %v", err)
		}
		second, err := CanonicalJSON(reparsed)
		if err != nil {
			t.Fatalf("canonical output cannot be re-canonicalized: %v", err)
		}
		if string(first) != string(second) {
			t.Fatalf("canonical JSON is not idempotent: %s != %s", first, second)
		}
	})
}

func FuzzParseTraceparent(f *testing.F) {
	f.Add("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	f.Add("bad")
	f.Fuzz(func(t *testing.T, header string) {
		parsed, err := ParseTraceparent(header)
		if err != nil {
			return
		}
		if parsed.Traceparent() != header ||
			len(parsed.TraceID) != 32 || len(parsed.SpanID) != 16 {
			t.Fatalf("traceparent did not round-trip: %+v", parsed)
		}
	})
}

func FuzzParseTimestampResp(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTimestampResp(data)
	})
}

func FuzzNormalizeConstraints(f *testing.F) {
	f.Add([]byte(`{"permissions":[]}`))
	f.Add([]byte(`{"predicates":[{"type":"max","path":"/attributes/amount","value":"1"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := DecodeJSON(data)
		if err != nil {
			return
		}
		_, _, _ = Normalize(AsMap(value))
	})
}

func FuzzBuildEvidenceSpans(f *testing.F) {
	f.Add("support.ticket.resolve", "dlg_1", "rcp_1")
	f.Fuzz(func(t *testing.T, action, delegationID, receiptID string) {
		hash := AuthorityHash(action, delegationID, receiptID)
		if len(hash) != 16 {
			t.Fatalf("authority hash has wrong size: %s", hash)
		}
	})
}
