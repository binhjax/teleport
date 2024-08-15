package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/oauth2"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	webPrefix        = "web"
	connectorsPrefix = "connectors"
	oidcPrefix       = "oidc"
)

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Phone         string   `json:"phone"`
	Subject       string   `json:"sub"`
	Profile       string   `json:"profile"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
	Roles         []string `json:"roles"`

	claims []byte
}
type stringAsBool bool

type userInfoRaw struct {
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Phone   string `json:"phone"`
	Subject string `json:"sub"`
	Profile string `json:"profile"`
	Email   string `json:"email"`
	// Handle providers that return email_verified as a string
	// https://forums.aws.amazon.com/thread.jspa?messageID=949441&#949441 and
	// https://discuss.elastic.co/t/openid-error-after-authenticating-against-aws-cognito/206018/11
	EmailVerified stringAsBool `json:"email_verified"`
	Groups        []string     `json:"groups"`
	Roles         []string     `json:"roles"`
}

// githubClient is internal structure that stores Github OAuth 2client and its config
type oidcClient struct {
	client *oauth2.Client
	config oauth2.Config
}

// formatGithubURL is a helper for formatting github api request URLs.
func formatOIDCURL(url string, path string) string {
	return fmt.Sprintf("%s/%s", url, strings.TrimPrefix(path, "/"))
}

type oidcManager interface {
	validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error)
}

type OIDCAuthService struct {
	lock        sync.RWMutex
	oidcClients map[string]*oidcClient

	Server   *Server
	Services *Services
}

// oidcAPIClient is a tiny wrapper around some of OIDC APIs
type oidcAPIClient struct {
	tokenType string
	// token is the access token retrieved during OAuth2 flow
	token string
	// authServer points to the Auth Server.
	authServer *OIDCAuthService
	// apiEndpoint is the API endpoint of the oidc instance
	// to connect to.
	apiUrl string
}

// get makes a GET request to the provided URL using the client's token for auth
func (c *oidcAPIClient) get(page string) ([]byte, string, error) {
	url := formatOIDCURL(c.apiUrl, page)
	fmt.Printf("binhnt.auth.oidc_binhnt.oidcAPIClient.get: url = %s \n", url)

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	// fmt.Printf("binhnt.auth.oidc_binhnt.oidcAPIClient.get:  c.tokenType = %s \n", c.tokenType)
	request.Header.Set("Authorization", fmt.Sprintf("%s %v", c.tokenType, c.token))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	defer response.Body.Close()
	bytes, err := utils.ReadAtMost(response.Body, teleport.MaxHTTPResponseSize)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", trace.AccessDenied("bad response: %v %v",
			response.StatusCode, string(bytes))
	}

	// Parse web links header to extract any pagination links. This is used to
	// return the next link which can be used in a loop to pull back all data.
	wls := utils.ParseWebLinks(response)

	return bytes, wls.NextPage, nil
}

// getEmails retrieves a list of emails for authenticated user
func (c *oidcAPIClient) getUser() (*UserInfo, error) {
	// Ignore pagination links, we should never get more than a single user here.
	bytes, _, err := c.get("userinfo")
	if err != nil {
		fmt.Printf("auth.oidc_binhnt.oidcAPIClient.getUser: user_info failed %s", err.Error())
		return nil, trace.Wrap(err)
	}
	// fmt.Printf("auth.oidc_binhnt.oidcAPIClient.getUser: body %s \n", string(bytes))

	var userInfo userInfoRaw
	err = json.Unmarshal(bytes, &userInfo)
	if err != nil {
		fmt.Printf("auth.oidc_binhnt.oidcAPIClient.getUser: Unmarshal failed %s", err.Error())

		return nil, trace.Wrap(err)
	}
	return &UserInfo{
		Name:          userInfo.Name,
		Picture:       userInfo.Picture,
		Phone:         userInfo.Phone,
		Subject:       userInfo.Subject,
		Profile:       userInfo.Profile,
		Email:         userInfo.Email,
		EmailVerified: bool(userInfo.EmailVerified),
		Groups:        userInfo.Groups,
		Roles:         userInfo.Roles,
		claims:        bytes,
	}, nil
}

func NewOIDCAuthService(service *Services, Server *Server) *OIDCAuthService {
	return &OIDCAuthService{
		oidcClients: make(map[string]*oidcClient),
		Services:    service,
		Server:      Server,
	}
}

func (a *OIDCAuthService) getOIDCConnectorAndClient(ctx context.Context, request types.OIDCAuthRequest) (types.OIDCConnector, *oauth2.Client, error) {
	fmt.Printf("binhnt.oidc_binhnt.getOIDCConnectorAndClient: start \n")

	// regular execution flow
	connector, err := a.Services.GetOIDCConnector(ctx, request.ConnectorID, true)
	if err != nil {
		fmt.Printf("binhnt.oidc_binhnt.getOIDCConnectorAndClient: GetOIDCConnector failed %s \n", err.Error())

		return nil, nil, trace.Wrap(err)
	}
	client, err := a.getOIDCOAuth2Client(connector)
	if err != nil {
		fmt.Printf("binhnt.oidc_binhnt.getOIDCConnectorAndClient: getOIDCOAuth2Client failed %s \n", err.Error())

		return nil, nil, trace.Wrap(err)
	}

	return connector, client, nil
}

func (a *OIDCAuthService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	fmt.Printf("binhnt.oidc_binhnt.CreateOIDCAuthRequest: start \n")
	connector, client, err := a.getOIDCConnectorAndClient(ctx, req)
	if err != nil {
		fmt.Printf("binhnt.oidc_binhnt.CreateOIDCAuthRequest: getOIDCConnectorAndClient failed %s \n", err.Error())
		return nil, trace.Wrap(err)
	}

	// requests for a web session originate from the proxy, so they are trusted
	// and they're handled in such a way that minimizes misuse in the callback
	// endpoint; requests for a client session (as used by tsh login) need to be
	// checked, as they will point the browser away from the IdP or the web UI
	// after the authentication is done
	if !req.CreateWebSession {
		if err := ValidateClientRedirect(req.ClientRedirectURL, req.SSOTestFlow, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	req.StateToken, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.RedirectURL = client.AuthCodeURL(req.StateToken, "", "")

	fmt.Printf("binhnt.oidc_binhnt.CreateOIDCAuthRequest: req.RedirectURL %s \n", req.RedirectURL)

	log.WithFields(logrus.Fields{teleport.ComponentKey: "github"}).Debugf(
		"Redirect URL: %v.", req.RedirectURL)

	// req.SetExpiry(a.Server.GetClock().Now().UTC().Add(defaults.OIDCAuthRequestTTL))

	ttl := defaults.OIDCAuthRequestTTL
	err = a.Services.CreateOIDCAuthRequest(ctx, req, ttl)
	if err != nil {
		fmt.Printf("binhnt.oidc_binhnt.CreateOIDCAuthRequest: CreateOIDCAuthRequest failed %s \n", err.Error())

		return nil, trace.Wrap(err)
	}
	return &req, nil
}

// populateOIDCClaims builds a OIDCClaims using queried
// user, organization and teams information.
func populateOIDCClaims(user *UserInfo) (types.OIDCClaims, error) {
	claims := types.OIDCClaims{
		"Username": user.Name,
		"Email":    user.Email,
		"Phone":    user.Phone,
		"Groups":   user.Groups,
		"Roles":    user.Roles,
	}
	log.WithFields(logrus.Fields{teleport.ComponentKey: "oidc"}).Debugf(
		"Claims: %#v.", claims)
	return claims, nil
}

// ValidateGithubAuthCallback validates Github auth callback redirect
func (a *OIDCAuthService) validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error) {
	fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback start %+v \n", q)
	// logger := log.WithFields(logrus.Fields{teleport.ComponentKey: "oidc"})

	if errParam := q.Get("error"); errParam != "" {
		// try to find request so the error gets logged against it.
		state := q.Get("state")
		if state != "" {
			diagCtx.RequestID = state
			req, err := a.Services.GetGithubAuthRequest(ctx, state)
			if err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}

		// optional parameter: error_description
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2(oauth2.ErrorInvalidRequest, errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "GitHub returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2(oauth2.ErrorInvalidRequest, "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from GitHub.")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2(oauth2.ErrorInvalidRequest, "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from GitHub.")
	}
	diagCtx.RequestID = stateToken

	req, err := a.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC Auth Request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	connector, client, err := a.getOIDCConnectorAndClient(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get GitHub connector and client.")
	}
	fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback code=%s \n", code)

	token, err := client.RequestToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback RequestToken failed: %s \n", err.Error())
		return nil, trace.Wrap(err, "Requesting OIDC OAuth2 token failed.")
	}

	diagCtx.Info.OIDCClaims = types.OIDCClaims{
		"TokenType": token.TokenType,
		"Expires":   int64(token.Expires),
		"Scope":     token.Scope,
	}

	fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: Obtained OAuth2 token: Type=%v Expires=%v Scope=%v \n",
		token.TokenType, token.Expires, token.Scope)

	// Get the UserInfo
	apiUrl := fmt.Sprintf("%s/api", connector.GetIssuerURL())
	// apiUrl := "http://10.10.66.108/api"
	fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: apiUrl = %s \n", apiUrl)
	// 2. Use oidcAPIClient
	oidcClient := &oidcAPIClient{
		tokenType:  token.TokenType,
		token:      token.AccessToken,
		authServer: a,
		apiUrl:     apiUrl,
	}
	userResp, err := oidcClient.getUser()
	if err != nil {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback oidcClient.getUser failed: %s \n", err.Error())
		return nil, trace.Wrap(err, "failed to query GitHub user info")
	}
	fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: userResp %+v \n", userResp)

	// Create claims
	claims, err := populateOIDCClaims(userResp)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to query GitHub API for user claims.")
	}

	diagCtx.Info.OIDCClaims = claims

	// Calculate (figure out name, roles, traits, session TTL) of user and
	// create the user in the backend.
	params, err := a.calculateOIDCUser(ctx, diagCtx, connector, claims, userResp, req)
	if err != nil {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: calculateOIDCUser failed %s ", err.Error())
		return nil, trace.Wrap(err, "Failed to calculate user attributes.")
	}
	fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: params: %+v \n", params)

	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: params.ConnectorName,
		Username:      params.Username,
		KubeGroups:    params.KubeGroups,
		KubeUsers:     params.KubeUsers,
		Roles:         params.Roles,
		Traits:        params.Traits,
		SessionTTL:    types.Duration(params.SessionTTL),
	}

	user, err := a.createOIDCUser(ctx, params, req.SSOTestFlow)
	if err != nil {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: createOIDCUser failed %s ", err.Error())

		return nil, trace.Wrap(err, "Failed to create user from provided parameters.")
	}

	if err := a.Server.CallLoginHooks(ctx, user); err != nil {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: CallLoginHooks failed %s ", err.Error())

		return nil, trace.Wrap(err)
	}

	userState, err := a.Server.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: GetUserOrLoginState failed %s ", err.Error())

		return nil, trace.Wrap(err)
	}

	// Auth was successful, return session, certificate, etc. to caller.
	auth := authclient.OIDCAuthResponse{
		Username: user.GetName(),
		Identity: types.ExternalIdentity{
			ConnectorID: params.ConnectorName,
			Username:    params.Username,
		},
		Session:     nil,                     //binhnt: web session
		Cert:        []byte{},                //binhnt: sshCert
		TLSCert:     []byte{},                //binhnt: tlsCert
		HostSigners: []types.CertAuthority{}, //binhnt: authority cluster
		Req: authclient.OIDCAuthRequest{
			ConnectorID:       req.ConnectorID,
			CSRFToken:         req.CSRFToken,
			PublicKey:         req.PublicKey,
			CreateWebSession:  req.CreateWebSession,
			ClientRedirectURL: req.ClientRedirectURL,
		},
	}

	// If the request is coming from a browser, create a web session.
	if req.CreateWebSession {
		session, err := a.Server.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:             userState.GetName(),
			Roles:            userState.GetRoles(),
			Traits:           userState.GetTraits(),
			SessionTTL:       params.SessionTTL,
			LoginTime:        a.Server.clock.Now().UTC(),
			LoginIP:          req.ClientLoginIP,
			AttestWebSession: true,
		})
		if err != nil {
			fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: CreateWebSession failed %s ", err.Error())

			return nil, trace.Wrap(err, "Failed to create web session.")
		}

		auth.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(req.PublicKey) != 0 {
		fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: req.PublicKey not nil ")

		sshCert, tlsCert, err := a.Server.CreateSessionCert(userState, params.SessionTTL, req.PublicKey, req.Compatibility, req.RouteToCluster,
			req.KubernetesCluster, req.ClientLoginIP, keys.AttestationStatementFromProto(req.AttestationStatement))
		if err != nil {
			fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: CreateSessionCert failed %s ", err.Error())

			return nil, trace.Wrap(err, "Failed to create session certificate.")
		}

		clusterName, err := a.Server.GetClusterName()
		if err != nil {
			fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: GetClusterName failed %s ", err.Error())

			return nil, trace.Wrap(err, "Failed to obtain cluster name.")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := a.Server.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			fmt.Printf("binhnt.auth.github.validateOIDCAuthCallback: GetCertAuthority failed %s ", err.Error())

			return nil, trace.Wrap(err, "Failed to obtain cluster's host CA.")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	return &auth, nil
}

func (a *OIDCAuthService) calculateOIDCUser(ctx context.Context,
	diagCtx *SSODiagContext,
	connector types.OIDCConnector,
	claims types.OIDCClaims,
	userRes *UserInfo,
	request *types.OIDCAuthRequest) (*CreateUserParams, error) {

	uRoles := []string{"editor", "auditor"}
	if len(userRes.Roles) > 0 {
		uRoles = userRes.Roles
	}
	groups := []string{}
	if len(userRes.Groups) > 0 {
		groups = userRes.Groups
	}
	p := CreateUserParams{
		ConnectorName: connector.GetName(),
		Username:      userRes.Name,
		Roles:         uRoles,
		KubeGroups:    groups,
		KubeUsers:     []string{},
	}

	// Calculate logins, kubegroups, roles, and traits.
	// p.Roles, p.KubeGroups, p.KubeUsers = connector.MapClaims(*claims)
	// if len(p.Roles) == 0 {
	// 	return nil, trace.Wrap(ErrGithubNoTeams)
	// }
	p.Traits = map[string][]string{
		constants.TraitLogins:     {p.Username},
		constants.TraitKubeGroups: p.KubeGroups,
		constants.TraitKubeUsers:  p.KubeUsers,
		// teleport.TraitTeams:       claims.Teams,
	}

	evaluationInput := &loginrule.EvaluationInput{
		Traits: p.Traits,
	}
	evaluationOutput, err := a.Server.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p.Traits = evaluationOutput.Traits
	diagCtx.Info.AppliedLoginRules = evaluationOutput.AppliedRules

	// Kube groups and users are ultimately only set in the traits, not any
	// other property of the User. In case the login rules changed the relevant
	// traits values, reset the value on the user params for accurate
	// diagnostics.
	p.KubeGroups = p.Traits[constants.TraitKubeGroups]
	p.KubeUsers = p.Traits[constants.TraitKubeUsers]

	// Pick smaller for role: session TTL from role or requested TTL.
	roles, err := services.FetchRoles(p.Roles, a.Services, p.Traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	p.SessionTTL = utils.MinTTL(roleTTL, request.CertTTL)

	fmt.Printf("binhnt.auth.oidc_binhnt.calculateOIDCUser: SessionTTL = %d ", p.SessionTTL)
	// p.SessionTTL = request.CertTTL //binhnt
	return &p, nil
}

func (a *OIDCAuthService) createOIDCUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: start %+v, dryRun = %t \n", p, dryRun)

	log.WithFields(logrus.Fields{teleport.ComponentKey: "oidc"}).Debugf(
		"Generating OIDC identity %v/%v with roles: %v. Dry run: %v.",
		p.ConnectorName, p.Username, p.Roles, dryRun)

	sessionTTL := p.SessionTTL
	if p.SessionTTL == 0 {
		sessionTTL = time.Duration(1000 * time.Second)
	}
	expires := a.Server.GetClock().Now().UTC().Add(sessionTTL)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: a.Server.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.Github,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: dryRun = true")

		return user, nil
	}

	existingUser, err := a.Services.GetUser(ctx, p.Username, false)

	if err != nil && !trace.IsNotFound(err) {
		fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: Services.GetUser: failed %+s \n", err.Error())
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: existingUser = %+v \n", existingUser)
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: local user %q already exists and is not a OIDC user \n ", existingUser.GetName())

			return nil, trace.AlreadyExists("local user %q already exists and is not a GitHub user",
				existingUser.GetName())
		}

		user.SetRevision(existingUser.GetRevision())

		fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: update user = %+v \n", user)
		if _, err := a.Server.UpdateUser(ctx, user); err != nil {
			fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: UpdateUser failed %s \n ", err.Error())

			return nil, trace.Wrap(err)
		}
	} else {
		fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: call Server.CreateUser = %+v \n", user)
		if _, err := a.Server.CreateUser(ctx, user); err != nil {
			fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: CreateUser failed %s \n ", err.Error())

			return nil, trace.Wrap(err)
		}
	}
	fmt.Printf("binhnt.auth.oidc_binhnt.createOIDCUser: final user = %+v \n", user)

	return user, nil
}

func (a *OIDCAuthService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	fmt.Printf("binhnt.local.oidc_binhnt.ValidateOIDCAuthCallback: req %+v \n", q)
	diagCtx := NewSSODiagContext(types.KindGithub, a.Services)
	return validateOIDCAuthCallbackHelper(ctx, a, diagCtx, q, a.Server.emitter)
}

func validateOIDCAuthCallbackHelper(ctx context.Context, m oidcManager, diagCtx *SSODiagContext, q url.Values, emitter apievents.Emitter) (*authclient.OIDCAuthResponse, error) {
	fmt.Printf("binhnt.local.oidc_binhnt.validateOIDCAuthCallbackHelper: req %+v \n", q)

	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodGithub,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	auth, err := m.validateOIDCAuthCallback(ctx, diagCtx, q)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	// claims := diagCtx.Info.OIDCClaims
	// if claims != nil {
	// 	attributes, err := apievents.EncodeMapStrings(claims)
	// 	if err != nil {
	// 		event.Status.UserMessage = fmt.Sprintf("Failed to encode identity attributes: %v", err.Error())
	// 		log.WithError(err).Debug("Failed to encode identity attributes.")
	// 	} else {
	// 		event.IdentityAttributes = attributes
	// 	}
	// }

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if err := emitter.EmitAuditEvent(ctx, event); err != nil {
			log.WithError(err).Warn("Failed to emit GitHub login failed event.")
		}
		return nil, trace.Wrap(err)
	}
	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = auth.Username

	if err := emitter.EmitAuditEvent(ctx, event); err != nil {
		log.WithError(err).Warn("Failed to emit GitHub login event.")
	}

	return auth, nil
}

func newOIDCOAuth2Config(connector types.OIDCConnector) oauth2.Config {
	fmt.Printf("binhnt.auth.oidc_binhnt.newOIDCOAuth2Config: connector %+v \n", connector)
	credentials := oauth2.ClientCredentials{
		ID:     connector.GetClientID(),
		Secret: connector.GetClientSecret(),
	}
	// credentials := oauth2.ClientCredentials{
	// 	ID:     "client1",
	// 	Secret: "89c557dbfb4494011547ec83277d35a4316583f0",
	// }

	// return oauth2.Config{
	// 	Credentials: credentials,
	// 	Scope:       OIDCScopes,
	// 	RedirectURL: "https://10.10.66.108:3080/v1/webapi/oidc/callback",
	// 	AuthURL:     "http://10.10.66.108/login/oauth/authorize",
	// 	TokenURL:    "http://10.10.66.108/api/login/oauth/access_token",
	// 	AuthMethod:  oauth2.AuthMethodClientSecretPost,
	// }

	return oauth2.Config{
		Credentials: credentials,
		Scope:       OIDCScopes,
		RedirectURL: connector.GetRedirectURLs()[0],
		AuthURL:     fmt.Sprintf("%s/%s", connector.GetIssuerURL(), "login/oauth/authorize"),
		TokenURL:    fmt.Sprintf("%s/%s", connector.GetIssuerURL(), "api/login/oauth/access_token"),
		AuthMethod:  oauth2.AuthMethodClientSecretPost,
	}
}

// OIDCScopes is a list of scopes requested during OAuth2 flow
// openid (no scope)	sub (user's id), iss (issuer), and aud (audience)
// profile	user profile info, including name, displayName, and avatar
// email	user's email address
// address	user's address
// phone	user's phone number
var OIDCScopes = []string{
	"openid",
	"profile",
	"email",
	"address",
	"phone",
}

func (a *OIDCAuthService) getOIDCOAuth2Client(connector types.OIDCConnector) (*oauth2.Client, error) {
	fmt.Printf("binhnt.local.oidc_binhnt.OIDCAuthService.getOIDCOAuth2Client: start \n")

	config := newOIDCOAuth2Config(connector)

	fmt.Printf("binhnt.local.oidc_binhnt.OIDCAuthService.getOIDCOAuth2Client: newOIDCOAuth2Config %+v \n", config)

	a.lock.Lock()
	defer a.lock.Unlock()

	cachedClient, ok := a.oidcClients[connector.GetName()]
	if ok && oauth2ConfigsEqual(cachedClient.config, config) {
		fmt.Printf("binhnt.local.oidc_binhnt.OIDCAuthService.getOIDCOAuth2Client: cachedClient.config %+v \n", cachedClient.config)

		return cachedClient.client, nil
	}

	delete(a.oidcClients, connector.GetName())
	client, err := oauth2.NewClient(http.DefaultClient, config)
	if err != nil {
		fmt.Printf("binhnt.local.oidc_binhnt.OIDCAuthService.getOIDCOAuth2Client: NewClient failed %s \n", err.Error())

		return nil, trace.Wrap(err)
	}
	a.oidcClients[connector.GetName()] = &oidcClient{
		client: client,
		config: config,
	}
	return client, nil
}
