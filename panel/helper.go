package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The root helper is veiltrium.sh --helper, started by systemd for each
// connection to its socket. Request: one line "<verb> [<client>]". Reply, line by line:
//
//	::step <id>     progress of a client change
//	::log <text>    a line of the installer's human output (no secrets)
//	::json <doc>    the result document (one line)
//	::exit <code>   the installer's exit code, always last
var (
	helperVerbs = map[string]bool{"status": false, "list-clients": false, "check-russia": false,
		"show-client": true, "add-client": true, "remove-client": true, "reset-client": true, "disable-client": true, "enable-client": true,
		"set-client": true, "audit": false}
	clientNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	stepRE       = regexp.MustCompile(`^[a-z-]{1,32}$`)
	// the whole argument of set-client, the same rule as HELPER_SET_RE in veiltrium.sh
	setArgRE = regexp.MustCompile(`^([a-z0-9][a-z0-9_-]{0,31}) limit=(none|[0-9]{1,16}) expires=(none|[0-9]{4}-[0-9]{2}-[0-9]{2}) reset=(none|daily|weekly|monthly)$`)
)

// HelperEvent is one reply line.
type HelperEvent struct {
	Kind string // step, log, json, exit
	Text string
	JSON json.RawMessage
	Code int
}

// HelperResult is the end of a call.
type HelperResult struct {
	JSON json.RawMessage
	Code int
	Log  []string // the last lines of human output (for error messages)
}

type Helper struct {
	Socket string
}

// SetClientArg builds the argument of set-client: "NAME limit=<bytes|none> expires=<date|none> reset=<mode>".
func SetClientArg(name string, limit *int64, expires, reset string) string {
	l := "none"
	if limit != nil {
		l = strconv.FormatInt(*limit, 10)
	}
	if expires == "" {
		expires = "none"
	}
	return name + " limit=" + l + " expires=" + expires + " reset=" + reset
}

// ValidRequest checks a verb and its argument before anything is sent.
func ValidRequest(verb, arg string) error {
	needsArg, ok := helperVerbs[verb]
	if !ok {
		return errors.New("unknown command")
	}
	if needsArg != (arg != "") {
		return errors.New("wrong arguments")
	}
	if verb == "set-client" {
		m := setArgRE.FindStringSubmatch(arg)
		if m == nil {
			return errors.New("bad limits: a size in bytes or none, a date YYYY-MM-DD or none, and none, daily, weekly or monthly")
		}
		if m[1] == "main" {
			return errors.New("the main client has no limits")
		}
		if m[3] != "none" {
			if _, err := time.Parse("2006-01-02", m[3]); err != nil {
				return errors.New("the expiry is not a real date (YYYY-MM-DD)")
			}
		}
		return nil
	}
	if arg != "" && arg != "main" && !clientNameRE.MatchString(arg) {
		return errors.New("a client name is 1-32 characters: a-z, 0-9, _ and -")
	}
	switch verb {
	case "add-client", "remove-client", "reset-client", "disable-client", "enable-client":
		if arg == "main" {
			return errors.New("the main client cannot be added, removed, reset, disabled or enabled")
		}
	}
	return nil
}

// Call runs one helper command; onEvent (may be nil) sees step and log lines as they come.
func (h *Helper) Call(ctx context.Context, verb, arg string, onEvent func(HelperEvent)) (*HelperResult, error) {
	if err := ValidRequest(verb, arg); err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", h.Socket)
	if err != nil {
		return nil, fmt.Errorf("the helper is not reachable: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	req := verb
	if arg != "" {
		req += " " + arg
	}
	if _, err := conn.Write([]byte(req + "\n")); err != nil {
		return nil, err
	}
	res := &HelperResult{Code: -1}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		ev, ok := parseHelperLine(sc.Text())
		if !ok {
			continue
		}
		switch ev.Kind {
		case "log":
			res.Log = append(res.Log, ev.Text)
			if len(res.Log) > 40 {
				res.Log = res.Log[len(res.Log)-40:]
			}
		case "json":
			res.JSON = ev.JSON
		case "exit":
			res.Code = ev.Code
			return res, nil
		}
		if onEvent != nil && (ev.Kind == "step" || ev.Kind == "log") {
			onEvent(ev)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("the helper ended without a result")
}

func parseHelperLine(line string) (HelperEvent, bool) {
	kind, rest, _ := strings.Cut(line, " ")
	switch kind {
	case "::step":
		if stepRE.MatchString(rest) {
			return HelperEvent{Kind: "step", Text: rest}, true
		}
	case "::log":
		return HelperEvent{Kind: "log", Text: rest}, true
	case "::json":
		if rest == "" || rest == "null" {
			return HelperEvent{Kind: "json"}, true
		}
		if json.Valid([]byte(rest)) {
			return HelperEvent{Kind: "json", JSON: json.RawMessage(rest)}, true
		}
	case "::exit":
		if c, err := strconv.Atoi(rest); err == nil {
			return HelperEvent{Kind: "exit", Code: c}, true
		}
	}
	return HelperEvent{}, false
}

// ErrorText is the reason a failed call gives: the installer's last "ERROR:" line.
func (r *HelperResult) ErrorText() string {
	for i := len(r.Log) - 1; i >= 0; i-- {
		if _, after, ok := strings.Cut(r.Log[i], "ERROR: "); ok {
			return strings.TrimSpace(after)
		}
	}
	return fmt.Sprintf("the command failed (exit code %d)", r.Code)
}
