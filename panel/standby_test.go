package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestStandbyAPI(t *testing.T) {
	token := "vt-standby-1|203.0.113.5|1793361600|" + strings.Repeat("a", 64) + "|" + strings.Repeat("b", 64)
	for _, bad := range []string{"", token + "\nstatus", token + ";id", "../receipt", strings.Repeat("x", 2000)} {
		if ValidRequest("verify-standby", bad) == nil {
			t.Fatalf("unsafe receipt accepted: %q", bad)
		}
	}
	if err := ValidRequest("verify-standby", token); err != nil {
		t.Fatal(err)
	}
	sock, requests := fakeHelper(t, func(req string) string {
		if req != "standby-status" && req != "verify-standby "+token {
			t.Errorf("unexpected helper command: %q", req)
		}
		return "::json {\"schema\":\"veiltrium-standby/1\",\"servers\":[]}\n::exit 0\n"
	})
	ts, client := newTestServer(t, sock)
	r := do(t, client, "GET", ts.URL+"/api/standby", "", nil)
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthed standby read: %d", r.StatusCode)
	}
	ck, _ := login(t, ts, client, "correct horse battery")
	headers := map[string]string{"Cookie": sessionCookie + "=" + ck.Value, csrfHeader: "1", "Origin": ts.URL}
	r = do(t, client, "POST", ts.URL+"/api/standby/verify", `{"receipt":"`+token+`"}`,
		map[string]string{"Cookie": sessionCookie + "=" + ck.Value, csrfHeader: "1", "Origin": "http://evil.example"})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin receipt: %d", r.StatusCode)
	}
	for _, body := range []string{`{"receipt":"bad"}`, `{"receipt":"` + token + `","extra":true}`, `{"receipt":"` + token + `"} {}`, `{"receipt":"` + strings.Repeat("a", 2000) + `"}`} {
		r = do(t, client, "POST", ts.URL+"/api/standby/verify", body, headers)
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed request: %d", r.StatusCode)
		}
	}
	r = do(t, client, "POST", ts.URL+"/api/standby/verify", `{"receipt":"`+token+`"}`, headers)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || len(*requests) != 1 || (*requests)[0] != "verify-standby "+token {
		t.Fatalf("valid receipt: %d", r.StatusCode)
	}
	r = do(t, client, "GET", ts.URL+"/api/standby", "", headers)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || len(*requests) != 2 || (*requests)[1] != "standby-status" {
		t.Fatalf("standby read: %d", r.StatusCode)
	}
}
