// veiltrium-panel: the Veiltrium web panel. It listens on the loopback interface only and is
// reached through an SSH tunnel; every action goes to the root helper (the installer in
// --helper mode) over a unix socket, so this process needs no privileges at all.
package main

import (
	"bufio"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

//go:embed all:web/dist
var webDist embed.FS

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "hash-password":
		hashPassword()
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  veiltrium-panel serve [--listen 127.0.0.1:2096] [--helper /run/veiltrium/helper.sock] [--auth /etc/veiltrium/panel-auth]
  veiltrium-panel hash-password   (reads the password from stdin, prints the hash line)
  veiltrium-panel version`)
}

func serve(args []string) {
	fl := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fl.String("listen", "127.0.0.1:2096", "address to listen on (loopback only)")
	socket := fl.String("helper", "/run/veiltrium/helper.sock", "root helper socket")
	auth := fl.String("auth", "/etc/veiltrium/panel-auth", "file with the password hash")
	_ = fl.Parse(args)
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !(host == "127.0.0.1" || host == "::1" || host == "localhost") {
		log.Fatalf("--listen must be a loopback address (127.0.0.1:PORT), got %q", *listen)
	}
	static, err := fs.Sub(webDist, "web/dist")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           NewServer(&Helper{Socket: *socket}, *auth, static).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("veiltrium-panel %s on http://%s (reach it through an SSH tunnel)", version, *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func hashPassword() {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		log.Fatal("no password on stdin")
	}
	h, err := HashPassword(strings.TrimRight(line, "\r\n"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(h)
}
