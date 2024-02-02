/*
 * Copyright (c) 2024 sixwaaaay.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"time"

	"errors"
	"net/http"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	autotls := &AutoTLS{}
	cmd := &cobra.Command{
		Use:   "autotls",
		Short: "autotls is a tool to get let's encrypt certificate automatically",
		Long:  `autotls is a tool to get let's encrypt certificate automatically`,
		Run: func(cmd *cobra.Command, args []string) {
			autotls.Run()
		},
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Panic(err)
	}

	cmd.Flags().StringVarP(&autotls.Dir, "dir", "d", "./autoTLS", "Directory to store the certificate get from let's encrypt")
	cmd.Flags().StringVarP(&autotls.Host, "host", "H", hostname, "Host is the domain name which you want to get certificate")

	if err := cmd.Execute(); err != nil {
		log.Panicf("execute: %s\n", err)
	}
}

type AutoTLS struct {
	// Dir Directory to store the certificate get from let's encrypt
	Dir string

	// Host is the domain name which you want to get certificate
	Host string
}

func (a *AutoTLS) Run() {
	autoCertManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(a.Host),
		Cache:      autocert.DirCache(a.Dir),
	}

	srv := &http.Server{
		Addr:    ":80", // 80 for http-01 challenge
		Handler: autoCertManager.HTTPHandler(nil),
	}

	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("listen: %s\n", err)
		}
	}()

	// trigger fetching certificate, random port
	listener, err := tls.Listen("tcp", ":0", &tls.Config{
		GetCertificate: autoCertManager.GetCertificate,
	})
	if err != nil {
		log.Panic(err)
	}
	defer listener.Close()
	go func() {
		if err := http.Serve(listener, nil); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("serve: %s\n", err)
		}
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: a.Host,
	})
	if err != nil {
		log.Panic(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %s\n", err)
	}
	cancel()
}
