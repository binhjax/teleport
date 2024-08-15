# Run in docker 
docker run -it -v $(pwd):/app -p 3080:3080   golang bash
cd /app
make all 

make build/teleport

docker exec -it 0f8e70ad365b bash 



- Make teleport
make build/teleport

 # Compare OSS 
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -tags "webassets_embed   kustomize_disable_go_plugin_support" -o build/teleport  -ldflags '-w -s ' -trimpath -buildmode=pie  ./tool/teleport

# Compile enterprise 
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -tags "webassets_embed webassets_ent   kustomize_disable_go_plugin_support" -o build/teleport  -ldflags '-w -s ' -trimpath -buildmode=pie  ./tool/teleport

# 

tctl sso configure oidc --name oidc_connector \
  --issuer-url  https://idp.example.com/ \
  --id <CLIENT-ID> \
  --secret $(cat client-secret.txt) \
  --claims-to-roles <CLAIM-KEY>,<CLAIM-VALUE>,access \
  --claims-to-roles <CLAIM-KEY>,<CLAIM-VALUE>,editor > oidc-connector.yaml

# Debug 
./build/teleport start --config /app/demo/teleport.yaml 



./build/tctl users add admin --roles=editor

./build/tctl users ls
./build/tctl users update admin --set-roles=editor,auditor

./build/tctl    users ls
./build/tctl    nodes ls 
./build/tctl    proxy ls

./build/tctl create demo/oidc.yaml


## Access 
https://localhost:3080/v1/webapi/oidc/login/web?connector_id=oidc_connector&redirect_url=https:%2F%2Flocalhost:3080%2Fweb


# TSH 
tsh --proxy=10.10.67.109:3080  --insecure  --auth=oidc_connector   login  --browser=none

## Control 
++ Users
++ Nodes/Apps/DB/Kube
++ Tokens
++ Auth
++ Requests 
++ Bots
++ Inventory
++ Alert 
++ Devices 
++ ACL
++ Audit 
++ Plugin 
++ SSO 



 help                            Show help.
  users add                       Generate a user invitation token [Teleport DB users only].
  users update                    Update user account.
  users ls                        Lists all user accounts.
  users rm                        Deletes user accounts.
  users reset                     Reset user password and generate a new token [Teleport DB users only].
 
 
  tokens add                      Create a invitation token.
  tokens rm                       Delete/revoke an invitation token.
  tokens ls                       List node and user invitation tokens.
  
  auth export                     Export public cluster CA certificates to stdout.
  auth sign                       Create an identity file(s) for a given user.
  auth rotate                     Rotate certificate authorities in the cluster.
  auth ls                         List connected auth servers.
  auth crl                        Export empty certificate revocation list (CRL) for certificate authorities.
  
  status                          Report cluster status.
  top                             Report diagnostic information.
  
  requests ls                     Show active access requests.
  requests get                    Show access request by ID.
  requests approve                Approve pending access request.
  requests deny                   Deny pending access request.
  requests create                 Create pending access request.
  requests rm                     Delete an access request.
  requests review                 Review an access request.
  
  nodes add                       Generate a node invitation token.
  nodes ls                        List all active SSH nodes within the cluster.
  apps ls                         List all applications registered with the cluster.
  db ls                           List all databases registered with the cluster.
  kube ls                         List all Kubernetes clusters registered with the cluster.
  windows_desktops ls             List all desktops registered with the cluster.
  
  lock                            Create a new lock.

  bots ls                         List all certificate renewal bots registered with the cluster.
  bots add                        Add a new certificate renewal bot to the cluster.
  bots rm                         Permanently remove a certificate renewal bot from the cluster.
  bots update                     Update an existing bot.
  
  inventory status                Show inventory status summary.
  inventory list                  List Teleport instance inventory.
  inventory ping                  Ping locally connected instance.
  
  recordings ls                   List recorded sessions.
  
  alerts list                     List cluster alerts.
  alerts create                   Create cluster alerts.
  alerts ack                      Acknowledge cluster alerts.
  alerts ack ls                   List acknowledged cluster alerts.
  proxy ls                        Lists proxies connected to the cluster.
  

  create                          Create or update a Teleport resource from a YAML file.
  update                          Update resource fields.
  rm                              Delete a resource.
  get                             Print a YAML declaration of various Teleport resources.
  edit                            Edit a Teleport resource.
  
  devices add                     Register managed devices.
  devices ls                      Lists managed devices.
  devices rm                      Removes a managed device.
  devices enroll                  Creates a new device enrollment token.
  devices lock                    Locks a device.
  
  saml export                     Export a SAML signing key in .crt format.
  acl ls                          List cluster access lists.
  acl get                         Get detailed information for an access list.
  acl users add                   Add a user to an access list.
  acl users rm                    Remove a user from an access list.
  acl users ls                    List users that are members of an access list.
  
  login_rule test                 Test the parsing and evaluation of login rules.
  
  idp saml test-attribute-mapping Test expression evaluation of attribute mapping.
  
  audit query get                 Get audit query.
  audit query rm                  Remove audit query.
  audit query ls                  List audit queries.
  audit query exec                Execute audit query.
  audit query create              Create an audit query.
  audit schema                    Print audit query schema.
  audit report ls                 List security reports.
  audit report get                Get security report.
  audit report run                Run the security report.
  audit report state              Print the state of the security report.
 
  plugins cleanup                 Cleans up the given plugin type.
  plugins install okta            Install an okta integration
  plugins install scim            Install a new SCIM integration
  plugins delete                  Remove a plugin instance
 
  sso configure github            Configure GitHub auth connector.
  sso configure saml              Configure SAML auth connector, optionally using a preset. Available presets: [okta onelogin ad adfs].
  sso configure oidc              Configure OIDC auth connector, optionally using a preset. Available presets: [google gitlab okta].
  sso test                        Perform end-to-end test of SSO flow using provided auth connector definition.

  version                         Print the version of your tctl binary.



./build/tctl    users add  --roles=ROLES [<flags>] <account>
Flags:
  -d, --[no-]debug            Enable verbose logging to stderr
  -c, --config                Path to a configuration file [/etc/teleport.yaml]. Can also be set via the TELEPORT_CONFIG_FILE environment variable.
      --auth-server           Attempts to connect to specific auth/proxy address(es) instead of local auth [127.0.0.1:3025]
  -i, --identity              Path to an identity file. Must be provided to make remote connections to auth. An identity file can be exported with 'tctl auth sign'
      --[no-]insecure         When specifying a proxy address in --auth-server, do not verify its TLS certificate. Danger: any data you send can be intercepted or modified by an attacker.
      --logins                List of allowed SSH logins for the new user
      --windows-logins        List of allowed Windows logins for the new user
      --kubernetes-users      List of allowed Kubernetes users for the new user
      --kubernetes-groups     List of allowed Kubernetes groups for the new user
      --db-users              List of allowed database users for the new user
      --db-names              List of allowed database names for the new user
      --db-roles              List of database roles for automatic database user provisioning
      --aws-role-arns         List of allowed AWS role ARNs for the new user
      --azure-identities      List of allowed Azure identities for the new user
      --gcp-service-accounts  List of allowed GCP service accounts for the new user
      --host-user-uid         UID for auto provisioned host users to use
      --host-user-gid         GID for auto provisioned host users to use
      --roles                 List of roles for the new user to assume
      --ttl                   Set expiration time for token, default is 1h0m0s, maximum is 48h0m0s

# Run teleport 
- Default /etc/teleport.yaml
- 
## Auth service 

## Proxy service 

## SSH service (SSH server)
- Create node config 
  teleport    node configure 
- Join an SSH server to a Teleport cluster
  teleport  join openssh
- 

## App service (SSH server)
  teleport app start

## DB agent (database agent)
    teleport db configure create   
    teleport db start 

## Integration
  integration configure deployservice-iam     Create the required IAM Roles for the AWS OIDC Deploy Service.
      --cluster     Teleport Cluster's name.
      --name        Integration name.
      --aws-region  AWS Region.
      --role        The AWS Role used by the AWS OIDC Integration.
      --task-role   The AWS Role to be used by the deployed service.


  integration configure eice-iam              Adds required IAM permissions to connect to EC2 Instances using EC2 Instance Connect Endpoint.
      --aws-region  AWS Region.
      --role        The AWS Role used by the AWS OIDC Integration.
  integration configure ec2-ssm-iam           Adds required IAM permissions and SSM Document to enable EC2 Auto Discover using SSM.

      --role               The AWS Role name used by the AWS OIDC Integration.
      --aws-region         AWS Region.
      --ssm-document-name  The AWS SSM Document name to create that will be used to install teleport.
      --proxy-public-url   Proxy Public URL (eg https://mytenant.teleport.sh).

  integration configure aws-app-access-iam    Adds required IAM permissions to connect to AWS using App Access.
     --role  The AWS Role name used by the AWS OIDC Integration.
  integration configure eks-iam               Adds required IAM permissions for enrollment of EKS clusters to Teleport.
      --aws-region  AWS Region.
      --role        The AWS Role used by the AWS OIDC Integration.
  integration configure access-graph aws-iam  Adds required IAM permissions for syncing data into Access Graph service.
    --role  The AWS Role used by the AWS OIDC Integration.
  integration configure awsoidc-idp           Creates an IAM IdP (OIDC) in your AWS account to allow the AWS OIDC Integration to access AWS APIs.
      --cluster           Teleport Cluster name.
      --name              Integration name.
      --role              The AWS Role used by the AWS OIDC Integration.
      --proxy-public-url  Proxy Public URL (eg https://mytenant.teleport.sh).
      --[no-]insecure     Insecure mode disables certificate validation.
      --s3-bucket-uri     The S3 URI(format: s3://<bucket>/<prefix>) used to store the OpenID configuration and public keys.
      --s3-jwks-base64    The JWKS base 64 encoded. Required when using the S3 Bucket as the Issuer URL. Format: base64({"keys":[{"kty":"RSA","alg":"RS256","n":"<value of n>","e":"<value of e>","use":"sig","kid":""}]}).


  integration configure listdatabases-iam     Adds required IAM permissions to List RDS Databases (Instances and Clusters).
      --aws-region  AWS Region.
      --role        The AWS Role used by the AWS OIDC Integration.
  integration configure externalauditstorage  Bootstraps required infrastructure and adds required IAM permissions for External Audit Storage logs.

      --[no-]bootstrap      Bootstrap required infrastructure.
      --aws-region          AWS region.
      --role                The IAM Role used by the AWS OIDC Integration.
      --policy              The name for the Policy to attach to the IAM role.
      --session-recordings  The S3 URI where session recordings are stored.
      --audit-events        The S3 URI where audit events are stored.
      --athena-results      The S3 URI where athena results are stored.
      --athena-workgroup    The name of the Athena workgroup used.
      --glue-database       The name of the Glue database used.
      --glue-table          The name of the Glue table used.
      --aws-partition       AWS partition (default: aws).
  integration configure samlidp gcp-workforce Configures GCP Workforce Identity Federation pool and SAML provider.
      --org-id              GCP organization ID.
      --pool-name           Name for the new workforce identity pool.
      --pool-provider-name  Name for the new workforce identity pool provider.
      --idp-metadata-url    Teleport SAML IdP metadata endpoint.

## Detail 

 db configure bootstrap 
    -c, --config       Path to a configuration file [/etc/teleport.yaml].
    --[no-]manual     When executed in "manual" mode, it will print the instructions to complete the configuration instead of applying them directly.
    --policy-name     Name of the Teleport Database agent policy. Default: "DatabaseAccess".
    --[no-]confirm    Do not prompt user and auto-confirm all actions.
    --attach-to-role  Role name to attach policy to. Mutually exclusive with --attach-to-user. If none of the attach-to flags is provided, the command will try to attach the policy to the current user/role based on the credentials.
    --attach-to-user  User name to attach policy to. Mutually exclusive with --attach-to-role. If none of the attach-to flags is provided, the command will try to attach the policy to the current user/role based on the credentials.
    --assumes-roles   Comma-separated list of additional IAM roles that the IAM identity should be able to assume. Each role can be either an IAM role ARN or the name of a role in the identity's account.



# Compile Tool
## tctl 

## teleport 

    help                                        Show help.
    start                                       Starts the Teleport service.
    status                                      Print the status of the current SSH session.
    configure                                   Generate a simple config file to get started.
    version                                     Print the version of your teleport binary.
    join openssh                                Join an SSH server to a Teleport cluster.
    app start                                   Start application proxy service.
    db start                                    Start database proxy service.
    db configure create                         Creates a sample Database Service configuration.
    db configure bootstrap                      Bootstrap the necessary configuration for the database agent. It reads the provided agent configuration to determine what will be bootstrapped.
    db configure aws print-iam                  Generate and show IAM policies.
    db configure aws create-iam                 Generate, create and attach IAM policies.
    discovery bootstrap                         Bootstrap the necessary configuration for the discovery agent . It reads the provided agent configuration to determine what will be bootstrapped.
    install systemd                             Creates a systemd unit file configuration.
    node configure                              Generate a configuration file for an SSH node.
    integration configure deployservice-iam     Create the required IAM Roles for the AWS OIDC Deploy Service.
    integration configure eice-iam              Adds required IAM permissions to connect to EC2 Instances using EC2 Instance Connect Endpoint.
    integration configure ec2-ssm-iam           Adds required IAM permissions and SSM Document to enable EC2 Auto Discover using SSM.
    integration configure aws-app-access-iam    Adds required IAM permissions to connect to AWS using App Access.
    integration configure eks-iam               Adds required IAM permissions for enrollment of EKS clusters to Teleport.
    integration configure access-graph aws-iam  Adds required IAM permissions for syncing data into Access Graph service.
    integration configure awsoidc-idp           Creates an IAM IdP (OIDC) in your AWS account to allow the AWS OIDC Integration to access AWS APIs.
    integration configure listdatabases-iam     Adds required IAM permissions to List RDS Databases (Instances and Clusters).
    integration configure externalauditstorage  Bootstraps required infrastructure and adds required IAM permissions for External Audit Storage logs.
    integration configure samlidp gcp-workforce Configures GCP Workforce Identity Federation pool and SAML provider.
    tpm identify                                Output identifying information related to the TPM detected on the system.
    debug set-log-level                         Changes the log level.
    debug get-log-level                         Fetches current log level.
    debug profile                               Export the application profiles (pprof format). Outputs to stdout .tar.gz file contents.