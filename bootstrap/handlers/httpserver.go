/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2021-2022 IOTech Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	commonDTO "github.com/edgexfoundry/go-mod-core-contracts/v3/dtos/common"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"

	"github.com/gorilla/mux"

	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
)

// HttpServer contains references to dependencies required by the http server implementation.
type HttpServer struct {
	router           *mux.Router
	isRunning        bool
	doListenAndServe bool
}

// NewHttpServer is a factory method that returns an initialized HttpServer receiver struct.
func NewHttpServer(router *mux.Router, doListenAndServe bool) *HttpServer {
	return &HttpServer{
		router:           router,
		isRunning:        false,
		doListenAndServe: doListenAndServe,
	}
}

// IsRunning returns whether or not the http server is running.  It is provided to support delayed shutdown of
// any resources required to successfully process http requests until after all outstanding requests have been
// processed (e.g. a database connection).
func (b *HttpServer) IsRunning() bool {
	return b.isRunning
}

// BootstrapHandler fulfills the BootstrapHandler contract.  It creates two go routines -- one that executes ListenAndServe()
// and another that waits on closure of a context's done channel before calling Shutdown() to cleanly shut down the
// http server.
func (b *HttpServer) BootstrapHandler(
	ctx context.Context,
	wg *sync.WaitGroup,
	_ startup.Timer,
	dic *di.Container) bool {

	lc := container.LoggingClientFrom(dic.Get)

	if !b.doListenAndServe {
		lc.Info("Web server intentionally NOT started.")
		wg.Add(1)
		go func() {
			defer wg.Done()

			b.isRunning = true
			<-ctx.Done()
			b.isRunning = false
		}()
		return true

	}

	bootstrapConfig := container.ConfigurationFrom(dic.Get).GetBootstrap()

	// this allows env override to explicitly set the value used
	// for ListenAndServe as needed for different deployments
	port := strconv.Itoa(bootstrapConfig.Service.Port)
	addr := bootstrapConfig.Service.ServerBindAddr + ":" + port
	// for backwards compatibility, the Host value is the default value if
	// the ServerBindAddr value is not specified
	if bootstrapConfig.Service.ServerBindAddr == "" {
		addr = bootstrapConfig.Service.Host + ":" + port
	}

	timeout, err := time.ParseDuration(bootstrapConfig.Service.RequestTimeout)
	if err != nil {
		lc.Errorf("unable to parse RequestTimeout value of %s to a duration: %v", bootstrapConfig.Service.RequestTimeout, err)
		return false
	}

	b.router.Use(func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, timeout, "HTTP request timeout")
	})

	b.router.Use(RequestLimitMiddleware(bootstrapConfig.Service.MaxRequestSize, lc))

	b.router.Use(ProcessCORS(bootstrapConfig.Service.CORSConfiguration))

	// handle the CORS preflight request
	b.router.Methods(http.MethodOptions).MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		return r.Header.Get(AccessControlRequestMethod) != ""
	}).HandlerFunc(HandlePreflight(bootstrapConfig.Service.CORSConfiguration))

	server := &http.Server{
		Addr:              addr,
		Handler:           b.router,
		ReadHeaderTimeout: 5 * time.Second, // G112: A configured ReadHeaderTimeout in the http.Server averts a potential Slowloris Attack
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		<-ctx.Done()
		_ = server.Shutdown(context.Background())
		lc.Info("Web server shut down")
	}()

	lc.Info("Web server starting (" + addr + ")")

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
			b.isRunning = false
		}()

		b.isRunning = true

		var ln net.Listener
		switch bootstrapConfig.Service.SecurityOptions["ListenMode"] {
		case "zerotrust":
			secretProvider := container.SecretProviderExtFrom(dic.Get)
			jwt, jwtErr := secretProvider.GetSelfJWT()
			if jwtErr != nil {
				lc.Errorf("could not load jwt: %v", jwtErr)
			}
			lc.Info("using zerotrust - look at you go: " + jwt)
			openZitiRootUrl := "https://" + bootstrapConfig.Service.SecurityOptions["OpenZitiController"]

			caPool, caErr := ziti.GetControllerWellKnownCaPool(openZitiRootUrl)
			if caErr != nil {
				panic(caErr)
			}

			credentials := edge_apis.NewJwtCredentials(jwt)
			credentials.CaPool = caPool

			cfg := &ziti.Config{
				ZtAPI:       openZitiRootUrl + "/edge/client/v1",
				Credentials: credentials,
			}
			cfg.ConfigTypes = append(cfg.ConfigTypes, "all")

			zitiCtx, ctxErr := ziti.NewContext(cfg)
			if ctxErr != nil {
				panic(ctxErr)
			}

			authErr := zitiCtx.Authenticate()
			if authErr != nil {
				panic(authErr)
			}

			serviceName := bootstrapConfig.Service.SecurityOptions["OpenZitiServiceName"]
			ln, err = zitiCtx.Listen(serviceName)

			if err != nil {
				log.Panicf("could not bind service %s: %v", serviceName, err)
			}
		case "http":
		default:
			lc.Warn("using ListenMode 'http'")
			ln, err = net.Listen("tcp", addr)
		}
		if err == nil {
			err = server.Serve(ln)
		}

		// "Server closed" error occurs when Shutdown above is called in the Done processing, so it can be ignored
		if err != nil && err != http.ErrServerClosed {
			// Other errors occur during bootstrapping, like port bind fails, are considered fatal
			lc.Errorf("Web server failed: %v", err)

			// Allow any long-running go functions that may have started to stop before exiting
			cancel := container.CancelFuncFrom(dic.Get)
			cancel()

			// Wait for all long-running go functions to stop before exiting.
			wg.Done() // Must do this to account for this go func's wg.Add above otherwise wait will block indefinitely
			wg.Wait()
			os.Exit(1)
		} else {
			lc.Info("Web server stopped")
		}
	}()

	return true
}

// RequestLimitMiddleware is a middleware function that limits the request body size to Service.MaxRequestSize in kilobytes
func RequestLimitMiddleware(sizeLimit int64, lc logger.LoggingClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				if sizeLimit > 0 && r.ContentLength > sizeLimit*1024 {
					response := commonDTO.NewBaseResponse("", fmt.Sprintf("request size exceed Service.MaxRequestSize(%d KB)", sizeLimit), http.StatusRequestEntityTooLarge)
					lc.Errorf(response.Message)

					w.Header().Set(common.ContentType, common.ContentTypeJSON)
					w.WriteHeader(response.StatusCode)
					if err := json.NewEncoder(w).Encode(response); err != nil {
						lc.Errorf("Error encoding the data:  %v", err)
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
				} else {
					next.ServeHTTP(w, r)
				}
			default:
				// ignore the other http methods because they do not have request bodies
				next.ServeHTTP(w, r)
			}
		})
	}
}
