//
// Copyright (C) 2022-2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"fmt"
	clientinterfaces "github.com/edgexfoundry/go-mod-core-contracts/v3/clients/interfaces"
	"net/http"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
)

type jwtSecretProvider struct {
	secretProvider interfaces.SecretProviderExt
	roundTripper_a http.RoundTripper
}

func NewJWTSecretProvider(secretProvider interfaces.SecretProviderExt) clientinterfaces.AuthenticationInjector {
	return &jwtSecretProvider{
		secretProvider: secretProvider,
	}
}
func NewJWTSecretProviderWithRT(secretProvider interfaces.SecretProviderExt, roundTripper_b http.RoundTripper) clientinterfaces.AuthenticationInjector {
	j := &jwtSecretProvider{
		secretProvider: secretProvider,
		roundTripper_a: roundTripper_b,
	}
	secretProvider.SetHttpTransport(roundTripper_b)
	return j
}

func (self *jwtSecretProvider) AddAuthenticationData(req *http.Request) error {
	if self.secretProvider == nil {
		// Test cases or real code may invoke NewJWTSecretProvider(nil),
		// though this is discouraged. In that case, just do nothing.
		return nil
	}

	// Otherwise if there is a secret provider, get the JWT
	jwt, err := self.secretProvider.GetSelfJWT()
	if err != nil {
		return err
	}

	// Only add authorization header if we get non-empty token back
	if len(jwt) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	}

	return nil
}
func (self *jwtSecretProvider) RoundTripper() http.RoundTripper {
	// Do nothing to the request; used for unit tests
	return self.secretProvider.HttpTransport()
}
