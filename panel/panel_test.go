package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("format: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("the right password is rejected")
	}
	for _, bad := range []string{"correct horse batter", "", "correct horse battery "} {
		if VerifyPassword(h, bad) {
			t.Fatalf("a wrong password is accepted: %q", bad)
		}
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("a short password is accepted")
	}
	for _, bad := range []string{"", "pbkdf2-sha256$1$AAAA$AAAA", "md5$600000$x$y", strings.Replace(h, "600000", "1000", 1)} {
		if VerifyPassword(bad, "correct horse battery") {
			t.Fatalf("a malformed hash is accepted: %q", bad)
		}
	}
}

func TestValidRequest(t *testing.T) {
	ok := [][2]string{{"status", ""}, {"list-clients", ""}, {"check-russia", ""}, {"show-client", "main"}, {"show-client", "anna"},
		{"add-client", "a_b-1"}, {"remove-client", "x"}}
	for _, c := range ok {
		if err := ValidRequest(c[0], c[1]); err != nil {
			t.Errorf("%v rejected: %v", c, err)
		}
	}
	bad := [][2]string{{"reboot", ""}, {"status", "x"}, {"show-client", ""}, {"show-client", "../x"},
		{"add-client", "Anna"}, {"add-client", "main"}, {"remove-client", "main"}, {"add-client", "a b"},
		{"add-client", "a;id"}, {"add-client", strings.Repeat("a", 33)}, {"show-client", "anna\nstatus"}, {"check-russia", "x"}}
	for _, c := range bad {
		if err := ValidRequest(c[0], c[1]); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
}

func TestLocalHost(t *testing.T) {
	for _, h := range []string{"localhost:8080", "127.0.0.1:2096", "[::1]:9", "LOCALHOST:1", "localhost"} {
		if !localHost(h) {
			t.Errorf("%s refused", h)
		}
	}
	for _, h := range []string{"evil.example:8080", "127.0.0.2:80", "localhost.evil.example", "192.0.2.1:2096", ""} {
		if localHost(h) {
			t.Errorf("%s accepted", h)
		}
	}
}

// fakeHelper answers like the real one: it records the request and plays a script.
func fakeHelper(t *testing.T, reply func(req string) string) (string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var reqs []string
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				line, _ := bufio.NewReader(c).ReadString('\n')
				req := strings.TrimSpace(line)
				mu.Lock()
				reqs = append(reqs, req)
				mu.Unlock()
				_, _ = io.WriteString(c, reply(req))
				c.Close()
			}()
		}
	}()
	return sock, &reqs
}

// TestCallsAreSerial: page loads fire status and clients at once; the helper runs the
// installer, which takes a lock, so the panel must send one request at a time.
func TestCallsAreSerial(t *testing.T) {
	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	sock, _ := fakeHelper(t, func(req string) string {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return "::json {\"ok\":true}\n::exit 0\n"
	})
	ts, c := newTestServer(t, sock)
	ck, _ := login(t, ts, c, "correct horse battery")
	cookie := map[string]string{"Cookie": sessionCookie + "=" + ck.Value}
	var wg sync.WaitGroup
	for _, p := range []string{"/api/status", "/api/clients", "/api/clients/main"} {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			r := do(t, c, "GET", ts.URL+p, "", cookie)
			r.Body.Close()
			if r.StatusCode != 200 {
				t.Errorf("%s: %d", p, r.StatusCode)
			}
		}(p)
	}
	wg.Wait()
	if maxInFlight != 1 {
		t.Fatalf("%d helper calls ran at once", maxInFlight)
	}
}

func newTestServer(t *testing.T, sock string) (*httptest.Server, *http.Client) {
	t.Helper()
	auth := filepath.Join(t.TempDir(), "auth")
	h, _ := HashPassword("correct horse battery")
	if err := os.WriteFile(auth, []byte(h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	static := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>Veiltrium</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")}}
	ts := httptest.NewServer(NewServer(&Helper{Socket: sock}, auth, static).Handler())
	t.Cleanup(ts.Close)
	return ts, ts.Client()
}

func do(t *testing.T, c *http.Client, method, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func login(t *testing.T, ts *httptest.Server, c *http.Client, pw string) (*http.Cookie, int) {
	t.Helper()
	resp := do(t, c, "POST", ts.URL+"/api/login", `{"password":"`+pw+`"}`, map[string]string{csrfHeader: "1", "Origin": ts.URL})
	defer resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			return ck, resp.StatusCode
		}
	}
	return nil, resp.StatusCode
}

func TestAPI(t *testing.T) {
	sock, reqs := fakeHelper(t, func(req string) string {
		switch {
		case req == "status":
			return "::log hello\n::json {\"schema\":\"veiltrium-status/1\"}\n::exit 0\n"
		case strings.HasPrefix(req, "add-client"):
			return "::step write\n::step restart\n::log ok\n::json {\"ok\":true}\n::exit 0\n"
		case strings.HasPrefix(req, "remove-client"):
			return "::step write\n::log ✖ ERROR: the change did not pass the checks\n::json null\n::exit 1\n"
		}
		return "::exit 1\n"
	})
	ts, c := newTestServer(t, sock)
	u := ts.URL

	// nothing without a session
	if r := do(t, c, "GET", u+"/api/status", "", nil); r.StatusCode != 401 {
		t.Fatalf("status without a session: %d", r.StatusCode)
	}
	// login needs the header and the same origin
	r := do(t, c, "POST", u+"/api/login", `{"password":"correct horse battery"}`, map[string]string{"Origin": u})
	if r.StatusCode != 403 {
		t.Fatalf("login without the CSRF header: %d", r.StatusCode)
	}
	r = do(t, c, "POST", u+"/api/login", `{"password":"correct horse battery"}`,
		map[string]string{csrfHeader: "1", "Origin": "http://evil.example"})
	if r.StatusCode != 403 {
		t.Fatalf("login from another origin: %d", r.StatusCode)
	}
	if ck, code := login(t, ts, c, "wrong password!"); ck != nil || code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	ck, code := login(t, ts, c, "correct horse battery")
	if ck == nil || code != 200 || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login: %d %+v", code, ck)
	}
	cookie := map[string]string{"Cookie": sessionCookie + "=" + ck.Value}

	r = do(t, c, "GET", u+"/api/status", "", cookie)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "veiltrium-status/1") {
		t.Fatalf("status: %d %s", r.StatusCode, b)
	}
	if r.Header.Get("Cache-Control") != "no-store" || !strings.Contains(r.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("API headers missing")
	}
	// a name the helper would refuse never reaches it
	before := len(*reqs)
	r = do(t, c, "GET", u+"/api/clients/..%2Fx", "", cookie)
	if r.StatusCode != 400 || len(*reqs) != before {
		t.Fatalf("bad client name: %d", r.StatusCode)
	}
	// a change without the header is refused even with a session
	h := map[string]string{"Cookie": cookie["Cookie"], "Origin": u}
	if r := do(t, c, "POST", u+"/api/clients", `{"name":"anna"}`, h); r.StatusCode != 403 {
		t.Fatalf("add without the CSRF header: %d", r.StatusCode)
	}
	h[csrfHeader] = "1"
	r = do(t, c, "POST", u+"/api/clients", `{"name":"anna"}`, h)
	b, _ = io.ReadAll(r.Body)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 || lines[0] != `{"step":"write"}` || !strings.Contains(lines[2], `"result":{"ok":true}`) {
		t.Fatalf("add stream: %q", lines)
	}
	if (*reqs)[len(*reqs)-1] != "add-client anna" {
		t.Fatalf("helper request: %q", (*reqs)[len(*reqs)-1])
	}
	r = do(t, c, "DELETE", u+"/api/clients/anna", "", h)
	b, _ = io.ReadAll(r.Body)
	var last map[string]string
	ls := strings.Split(strings.TrimSpace(string(b)), "\n")
	_ = json.Unmarshal([]byte(ls[len(ls)-1]), &last)
	if last["error"] != "the change did not pass the checks" {
		t.Fatalf("remove error: %q", b)
	}
	if r := do(t, c, "DELETE", u+"/api/clients/main", "", h); r.StatusCode != 400 {
		t.Fatalf("removing main: %d", r.StatusCode)
	}
	// logout ends the session
	do(t, c, "POST", u+"/api/logout", "", h)
	if r := do(t, c, "GET", u+"/api/status", "", cookie); r.StatusCode != 401 {
		t.Fatalf("status after logout: %d", r.StatusCode)
	}
}

func TestHostAndRateLimit(t *testing.T) {
	sock, _ := fakeHelper(t, func(string) string { return "::exit 0\n" })
	ts, c := newTestServer(t, sock)
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "rebind.evil.example"
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host: %d", r.StatusCode)
	}
	r = do(t, c, "GET", ts.URL+"/clients", "", nil) // the app's own routes fall back to index.html
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "<title>Veiltrium</title>") {
		t.Fatalf("index fallback: %d", r.StatusCode)
	}
	for i := 0; i < 5; i++ {
		login(t, ts, c, "wrong password!")
	}
	if ck, code := login(t, ts, c, "correct horse battery"); ck != nil || code != 429 {
		t.Fatalf("after 5 failures the right password must wait: %d", code)
	}
}

func TestHelperTimeout(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			time.Sleep(2 * time.Second) // never answers in time
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (&Helper{Socket: sock}).Call(ctx, "status", "", nil); err == nil {
		t.Fatal("no error after the timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("the timeout was not honoured")
	}
}

// TestBusyAndUnknownAPI: helper exit 75 is "the installer lock is busy" (503, and the same
// text in the change stream); an unregistered /api/ path is a JSON 404, not the web page.
func TestBusyAndUnknownAPI(t *testing.T) {
	sock, _ := fakeHelper(t, func(req string) string {
		if strings.HasPrefix(req, "add-client") {
			return "::exit 75\n"
		}
		if req == "status" {
			return "::log ERROR: another run holds the lock\n::exit 75\n"
		}
		return "::exit 1\n"
	})
	ts, c := newTestServer(t, sock)
	u := ts.URL
	ck, _ := login(t, ts, c, "correct horse battery")
	h := map[string]string{"Cookie": sessionCookie + "=" + ck.Value, "Origin": u, csrfHeader: "1"}

	r := do(t, c, "GET", u+"/api/status", "", h)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 503 || !strings.Contains(string(b), "another run holds the lock") {
		t.Fatalf("busy status: %d %s", r.StatusCode, b)
	}
	r = do(t, c, "GET", u+"/api/clients", "", h)
	b, _ = io.ReadAll(r.Body)
	if r.StatusCode != 409 {
		t.Fatalf("other failure: %d %s", r.StatusCode, b)
	}
	r = do(t, c, "POST", u+"/api/clients", `{"name":"anna"}`, h)
	b, _ = io.ReadAll(r.Body)
	if !strings.Contains(string(b), `"error":"the server is busy`) {
		t.Fatalf("busy change: %s", b)
	}
	r = do(t, c, "GET", u+"/api/nope", "", h)
	b, _ = io.ReadAll(r.Body)
	if r.StatusCode != 404 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || !strings.Contains(string(b), `"error"`) {
		t.Fatalf("unknown API path: %d %s", r.StatusCode, b)
	}
	if r := do(t, c, "GET", u+"/some/page", "", nil); r.StatusCode != 200 {
		t.Fatalf("SPA fallback: %d", r.StatusCode)
	}
}
