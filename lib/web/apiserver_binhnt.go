package web

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
)

func (h *Handler) oidcLoginWeb(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
	fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: start \n")
	logger := h.log.WithField("auth", "oidc")
	logger.Debug("Web login start.")

	req, err := ParseSSORequestParams(r)
	if err != nil {
		fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: ParseSSORequestParams failed %s \n", err.Error())

		logger.WithError(err).Error("Failed to extract SSO parameters from request.")
		return client.LoginFailedRedirectURL
	}

	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: SplitHostPort failed %s \n", err.Error())

		logger.WithError(err).Error("Failed to parse request remote address.")
		return client.LoginFailedRedirectURL
	}

	fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: connectorID %s \n", req.ConnectorID)

	response, err := h.cfg.ProxyClient.CreateOIDCAuthRequest(r.Context(), types.OIDCAuthRequest{
		CSRFToken:         req.CSRFToken,
		ConnectorID:       req.ConnectorID,
		CreateWebSession:  true,
		ClientRedirectURL: req.ClientRedirectURL,
		ClientLoginIP:     remoteAddr,
	})
	if err != nil {
		fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: CreateOIDCAuthRequest failed %s \n", err.Error())

		logger.WithError(err).Error("Error creating auth request.")
		return client.LoginFailedRedirectURL

	}

	return response.RedirectURL
}

func (h *Handler) oidcLoginConsole(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	fmt.Printf("binhnt.web.apiserver.oidcLoginConsole: start \n")

	logger := h.log.WithField("auth", "oidc")
	logger.Debug("Console login start.")

	req := new(client.SSOLoginConsoleReq)
	if err := httplib.ReadJSON(r, req); err != nil {
		logger.WithError(err).Error("Error reading json.")
		return nil, trace.AccessDenied(SSOLoginFailureMessage)
	}

	if err := req.CheckAndSetDefaults(); err != nil {
		logger.WithError(err).Error("Missing request parameters.")
		return nil, trace.AccessDenied(SSOLoginFailureMessage)
	}

	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.WithError(err).Error("Failed to parse request remote address.")
		return nil, trace.AccessDenied(SSOLoginFailureMessage)
	}
	fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: connectorID %s \n", req.ConnectorID)

	response, err := h.cfg.ProxyClient.CreateOIDCAuthRequest(r.Context(), types.OIDCAuthRequest{
		ConnectorID:          req.ConnectorID,
		PublicKey:            req.PublicKey,
		CertTTL:              req.CertTTL,
		ClientRedirectURL:    req.RedirectURL,
		Compatibility:        req.Compatibility,
		RouteToCluster:       req.RouteToCluster,
		KubernetesCluster:    req.KubernetesCluster,
		AttestationStatement: req.AttestationStatement.ToProto(),
		ClientLoginIP:        remoteAddr,
	})
	if err != nil {
		logger.WithError(err).Error("Failed to create GitHub auth request.")
		if strings.Contains(err.Error(), auth.InvalidClientRedirectErrorMessage) {
			return nil, trace.AccessDenied(SSOLoginFailureInvalidRedirect)
		}
		return nil, trace.AccessDenied(SSOLoginFailureMessage)
	}

	return &client.SSOLoginConsoleResponse{
		RedirectURL: response.RedirectURL,
	}, nil
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
	// fmt.Printf("binhnt.web.apiserver.oidcCallback: start %s \n", r.URL.Query())

	logger := h.log.WithField("auth", "oidc")
	logger.Debugf("Callback start: %v.", r.URL.Query())

	response, err := h.cfg.ProxyClient.ValidateOIDCAuthCallback(r.Context(), r.URL.Query())
	if err != nil {
		fmt.Printf("binhnt.web.apiserver.oidcCallback: ValidateOIDCAuthCallback failed: %s \n", err.Error())

		logger.WithError(err).Error("Error while processing callback.")

		// try to find the auth request, which bears the original client redirect URL.
		// if found, use it to terminate the flow.
		//
		// this improves the UX by terminating the failed SSO flow immediately, rather than hoping for a timeout.
		if requestID := r.URL.Query().Get("state"); requestID != "" {
			fmt.Printf("binhnt.web.apiserver.oidcCallback: ValidateOIDCAuthCallback requestID = %s \n", requestID)

			if request, errGet := h.cfg.ProxyClient.GetOIDCAuthRequest(r.Context(), requestID); errGet == nil && !request.CreateWebSession {
				fmt.Printf("binhnt.web.apiserver.oidcCallback: ValidateOIDCAuthCallback GetOIDCAuthRequest = %+v \n", request)

				if redURL, errEnc := RedirectURLWithError(request.ClientRedirectURL, err); errEnc == nil {
					return redURL.String()
				}
			}
		}

		return client.LoginFailedBadCallbackRedirectURL
	}

	// fmt.Printf("binhnt.web.apiserver.oidcCallback: response: %+v \n", response)

	// if we created web session, set session cookie and redirect to original url
	if response.Req.CreateWebSession {
		fmt.Printf("binhnt.web.apiserver.oidcCallback: Req.CreateWebSession => Redirecting to web browser \n")

		logger.Infof("Redirecting to web browser.")

		res := &SSOCallbackResponse{
			CSRFToken:         response.Req.CSRFToken,
			Username:          response.Username,
			SessionName:       response.Session.GetName(),
			ClientRedirectURL: response.Req.ClientRedirectURL,
		}

		fmt.Printf("binhnt.web.apiserver.oidcCallback: ClientRedirectURL=%s \n", response.Req.ClientRedirectURL)

		if err := SSOSetWebSessionAndRedirectURL(w, r, res, true); err != nil {
			fmt.Printf("binhnt.web.apiserver.oidcCallback: SSOSetWebSessionAndRedirectURL failed %s  \n", err.Error())

			logger.WithError(err).Error("Error setting web session.")
			return client.LoginFailedRedirectURL
		}

		fmt.Printf("binhnt.web.apiserver.oidcCallback: res.ClientRedirectURL  %s  \n", res.ClientRedirectURL)

		return res.ClientRedirectURL
	}

	logger.Infof("Callback is redirecting to console login.")
	// fmt.Printf("binhnt.web.apiserver.oidcCallback: response.Req.PublicKey  %+v \n", response.Req.PublicKey)

	if len(response.Req.PublicKey) == 0 {
		fmt.Printf("binhnt.web.apiserver.oidcLoginWeb: response.Req.PublicKey empty")

		logger.Error("Not a web or console login request.")
		return client.LoginFailedRedirectURL
	}

	redirectURL, err := ConstructSSHResponse(AuthParams{
		ClientRedirectURL: response.Req.ClientRedirectURL,
		Username:          response.Username,
		Identity:          response.Identity,
		Session:           response.Session,
		Cert:              response.Cert,
		TLSCert:           response.TLSCert,
		HostSigners:       response.HostSigners,
		FIPS:              h.cfg.FIPS,
	})
	if err != nil {
		fmt.Printf("binhnt.web.apiserver.oidcCallback: ConstructSSHResponse failed  %s \n", err.Error())

		logger.WithError(err).Error("Error constructing ssh response")
		return client.LoginFailedRedirectURL
	}

	return redirectURL.String()
}
