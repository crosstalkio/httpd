package httpd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"path/filepath"

	"github.com/crosstalkio/log"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
)

func GetCertFileConfig(s log.Sugar, keyFile, crtFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		s.Errorf("Failed to load certs: %s", err.Error())
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}}, nil
}

func GetAutoDomainCertConfig(s log.Sugar, domain, email, cacheDir string) (*tls.Config, error) {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  email,
	}
	if cacheDir != "" {
		dir, err := filepath.Abs(cacheDir)
		if err != nil {
			s.Errorf("Failed to get absolute path of cert cache: %s", err.Error())
			return nil, err
		}
		m.Cache = autocert.DirCache(dir)
	}
	m.HostPolicy = func(c context.Context, host string) error {
		if !strings.HasSuffix(host, domain) {
			s.Warningf("Not expected domain: %s", host)
			return fmt.Errorf("Not allowed")
		}
		return nil
	}
	return m.TLSConfig(), nil
}

func GetAutoHostCertConfig(s log.Sugar, hostname, email, cacheDir string) (*tls.Config, error) {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  email,
	}
	if cacheDir != "" {
		dir, err := filepath.Abs(cacheDir)
		if err != nil {
			s.Errorf("Failed to get absolute path of cert cache: %s", err.Error())
			return nil, err
		}
		m.Cache = autocert.DirCache(dir)
	}
	m.HostPolicy = func(_ context.Context, host string) error {
		if host != hostname {
			return fmt.Errorf("Hostname mismatch: expect=%q, was=%q", hostname, host)
		}
		return nil
	}
	cfg := m.TLSConfig()
	getCert := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			hello.ServerName = hostname
		}
		return getCert(hello)
	}
	return cfg, nil
}

func BindHTTP(s log.Sugar, port int, h http.Handler, tlsConfig *tls.Config) error {
	var lis net.Listener
	var err error
	if tlsConfig == nil {
		s.Infof("Listening HTTP on port %d", port)
		lis, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			s.Errorf("Failed to listen %d: %s", port, err.Error())
			return err
		}
	} else {
		s.Infof("Listening HTTP with TLS on port %d", port)
		lis, err = tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
		if err != nil {
			s.Errorf("Failed to listen %d with TLS: %s", port, err.Error())
			return err
		}
	}
	srv := &http.Server{
		Handler: h,
	}
	return srv.Serve(lis)
}

func BindGRPC(s log.Sugar, port int, grpc *grpc.Server, tlsConfig *tls.Config) error {
	var lis net.Listener
	var err error
	if tlsConfig == nil {
		s.Infof("Listening GRPC on port %d", port)
		lis, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			s.Errorf("Failed to listen %d: %s", port, err.Error())
			return err
		}
	} else {
		s.Infof("Listening GRPC with TLS on port %d", port)
		lis, err = tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
		if err != nil {
			s.Errorf("Failed to listen %d: %s", port, err.Error())
			return err
		}
	}
	return grpc.Serve(lis)
}
