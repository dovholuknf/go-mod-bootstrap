package container

import (
	"context"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
	"net"
	"net/http"
	"strings"
)

const (
	OpenZitiControllerKey = "OpenZitiController"
	ZeroTrustKey          = "zerotrust"
)

func AuthToOpenZiti(ozController, jwt string) ziti.Context {
	openZitiRootUrl := "https://" + ozController
	if !strings.Contains(openZitiRootUrl, "://") {
		openZitiRootUrl = "https://" + ozController
	}
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

	ctx, ctxErr := ziti.NewContext(cfg)
	if ctxErr != nil {
		panic(ctxErr)
	}
	if err := ctx.Authenticate(); err != nil {
		panic(err)
	}

	return ctx
}

func isZeroTrust(secOpts map[string]string) bool {
	return secOpts != nil && secOpts["Mode"] == ZeroTrustKey
}

func HttpTransportFromService(secretProvider interfaces.SecretProviderExt, serviceInfo config.ServiceInfo, lc logger.LoggingClient) http.RoundTripper {
	roundTripper := http.DefaultTransport
	not := "NOT"
	if isZeroTrust(serviceInfo.SecurityOptions) {
		lc.Infof("zero trust client detected for service: %s", serviceInfo.Host)
		roundTripper = createZitifiedTransport(secretProvider, serviceInfo.SecurityOptions[OpenZitiControllerKey], lc)
		not = "YES!"
	}
	lc.Warnf("%s USING ZERO TRUST: %s", not, serviceInfo.Host)
	lc.Warnf("%s USING ZERO TRUST: %s", not, serviceInfo.Host)
	return roundTripper
}

func HttpTransportFromClient(secretProvider interfaces.SecretProviderExt, clientInfo *config.ClientInfo, lc logger.LoggingClient) http.RoundTripper {
	roundTripper := http.DefaultTransport
	not := "NOT"
	if isZeroTrust(clientInfo.SecurityOptions) {
		lc.Infof("zero trust client detected for client: %s", clientInfo.Host)
		roundTripper = createZitifiedTransport(secretProvider, clientInfo.SecurityOptions[OpenZitiControllerKey], lc)
		not = "YES!"
	}
	lc.Warnf("%s USING ZERO TRUST: %s", not, clientInfo.Host)
	lc.Warnf("%s USING ZERO TRUST: %s", not, clientInfo.Host)
	lc.Warnf("%s USING ZERO TRUST: %s", not, clientInfo.Host)
	lc.Warnf("%s USING ZERO TRUST: %s", not, clientInfo.Host)
	return roundTripper
}

func createZitifiedTransport(secretProvider interfaces.SecretProviderExt, ozController string, lc logger.LoggingClient) http.RoundTripper {
	jwt, errJwt := secretProvider.GetSelfJWT()
	if errJwt != nil {
		lc.Errorf("could not load jwt: %v", errJwt)
		return nil
	}
	ctx := AuthToOpenZiti(ozController, jwt)

	zitiContexts := ziti.NewSdkCollection()
	zitiContexts.Add(ctx)

	zitiTransport := http.DefaultTransport.(*http.Transport).Clone() // copy default transport
	zitiTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		lc.Infof("ZITI DIALING: %s", addr)
		dialer := zitiContexts.NewDialerWithFallback(ctx /*&net.Dialer{}*/, nil)
		return dialer.Dial(network, addr)
	}
	return zitiTransport
}
