package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "vt_session"
	sessionIdle   = 2 * time.Hour
	sessionMax    = 12 * time.Hour
	csrfHeader    = "X-Veiltrium"
)

type session struct {
	created, seen time.Time
}

type Server struct {
	helper   *Helper
	authFile string
	static   fs.FS

	mu       sync.Mutex
	sessions map[string]*session
	failures []time.Time // failed logins, for the rate limit
	busy     bool        // a client change is running
}

func NewServer(helper *Helper, authFile string, static fs.FS) *Server {
	return &Server{helper: helper, authFile: authFile, static: static, sessions: map[string]*session{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/session", s.authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/status", s.authed(s.simple("status")))
	mux.HandleFunc("GET /api/clients", s.authed(s.simple("list-clients")))
	mux.HandleFunc("GET /api/clients/{name}", s.authed(s.showClient))
	mux.HandleFunc("POST /api/clients", s.authed(s.addClient))
	mux.HandleFunc("DELETE /api/clients/{name}", s.authed(s.removeClient))
	mux.Handle("GET /", s.staticHandler())
	return s.guard(mux)
}

// guard: local host names only (a DNS-rebinding page cannot talk to the panel), the same
// origin and a custom header on every API change (no cross-site requests), strict headers.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !localHost(r.Host) {
			http.Error(w, "use the SSH tunnel: http://localhost:<port>/", http.StatusMisdirectedRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if r.Header.Get(csrfHeader) != "1" || !sameOrigin(r) {
					writeError(w, http.StatusForbidden, "cross-site request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func localHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// sameOrigin: an Origin header (browsers send it on POST and DELETE) must name this host.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host == r.Host
}

// ---- sessions ------------------------------------------------------------------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	now := time.Now()
	s.mu.Lock()
	recent := s.failures[:0]
	for _, t := range s.failures {
		if now.Sub(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	s.failures = recent
	limited := len(recent) >= 5
	s.mu.Unlock()
	if limited {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again in a few minutes")
		return
	}
	hash, err := readHash(s.authFile)
	if err != nil {
		log.Printf("login: %v", err)
		writeError(w, http.StatusServiceUnavailable, "no panel password is set: bash veiltrium.sh --panel-password")
		return
	}
	if !VerifyPassword(hash, body.Password) {
		s.mu.Lock()
		s.failures = append(s.failures, now)
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	id := randomID()
	s.mu.Lock()
	s.sessions[id] = &session{created: now, seen: now}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMax / time.Second)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		ok := false
		if err == nil {
			now := time.Now()
			s.mu.Lock()
			for id, se := range s.sessions { // drop expired sessions
				if now.Sub(se.seen) > sessionIdle || now.Sub(se.created) > sessionMax {
					delete(s.sessions, id)
				}
			}
			if se, found := s.sessions[c.Value]; found {
				se.seen = now
				ok = true
			}
			s.mu.Unlock()
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		next(w, r)
	}
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ---- API -----------------------------------------------------------------------

func (s *Server) simple(verb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.run(w, r, verb, "") }
}

func (s *Server) showClient(w http.ResponseWriter, r *http.Request) {
	s.run(w, r, "show-client", r.PathValue("name"))
}

func (s *Server) run(w http.ResponseWriter, r *http.Request, verb, arg string) {
	if err := ValidRequest(verb, arg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.helper.Call(ctx, verb, arg, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if res.Code != 0 || res.JSON == nil {
		writeError(w, http.StatusConflict, res.ErrorText())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res.JSON)
}

func (s *Server) addClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	s.change(w, r, "add-client", body.Name)
}

func (s *Server) removeClient(w http.ResponseWriter, r *http.Request) {
	s.change(w, r, "remove-client", r.PathValue("name"))
}

// change streams a client change as NDJSON: {"step":…} lines, then {"result":…} or {"error":…}.
// It runs to the end even if the browser goes away: the installer finishes or rolls back.
func (s *Server) change(w http.ResponseWriter, r *http.Request, verb, name string) {
	if err := ValidRequest(verb, name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "another change is running; wait for it to finish")
		return
	}
	s.busy = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.busy = false; s.mu.Unlock() }()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	var wmu sync.Mutex
	emit := func(v any) {
		wmu.Lock()
		defer wmu.Unlock()
		if enc.Encode(v) == nil && flusher != nil {
			flusher.Flush()
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer cancel()
	res, err := s.helper.Call(ctx, verb, name, func(ev HelperEvent) {
		if ev.Kind == "step" {
			emit(map[string]string{"step": ev.Text})
		}
	})
	switch {
	case err != nil:
		emit(map[string]string{"error": err.Error()})
	case res.Code != 0 || res.JSON == nil:
		emit(map[string]string{"error": res.ErrorText()})
	default:
		emit(map[string]json.RawMessage{"result": res.JSON})
	}
}

// ---- static files (the built web interface) -------------------------------------

func (s *Server) staticHandler() http.Handler {
	files := http.FileServerFS(s.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.static, p); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/" // the app has one page
			files.ServeHTTP(w, r2)
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
