# Login 
- Init connectors 
grpcServer => ServerWithRoles => LocalUsers

authServer = local_users.IdentityService

- Login 
  apiserver (oidcLoginWeb) (
    CreateOIDCAuthRequest =  authclient
  ) => auth.grpcserver 
  ( authenticate(ctx) = ServerWithRoles  )
  (CreateOIDCAuthRequest) => ServerWithRoles (CreateOIDCAuthRequest) (
    authServer == 
  ) => auth Server - oidc (CreateOIDCAuthRequest) => 

# Auth  
 - services_local_user 
 - auth/authclient 
 - 
# Create connectors 
- Create connectors
  grpcServer => ServerWithRoles => auth (Server) - oidc => local_users.IdentityService

