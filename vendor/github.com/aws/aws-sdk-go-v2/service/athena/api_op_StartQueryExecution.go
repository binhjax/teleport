// Code generated by smithy-go-codegen DO NOT EDIT.

package athena

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Runs the SQL query statements contained in the Query . Requires you to have
// access to the workgroup in which the query ran. Running queries against an
// external catalog requires GetDataCatalog permission to the catalog. For code
// samples using the Amazon Web Services SDK for Java, see Examples and Code
// Samples (http://docs.aws.amazon.com/athena/latest/ug/code-samples.html) in the
// Amazon Athena User Guide.
func (c *Client) StartQueryExecution(ctx context.Context, params *StartQueryExecutionInput, optFns ...func(*Options)) (*StartQueryExecutionOutput, error) {
	if params == nil {
		params = &StartQueryExecutionInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "StartQueryExecution", params, optFns, c.addOperationStartQueryExecutionMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*StartQueryExecutionOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type StartQueryExecutionInput struct {

	// The SQL query statements to be executed.
	//
	// This member is required.
	QueryString *string

	// A unique case-sensitive string used to ensure the request to create the query
	// is idempotent (executes only once). If another StartQueryExecution request is
	// received, the same response is returned and another query is not created. An
	// error is returned if a parameter, such as QueryString , has changed. A call to
	// StartQueryExecution that uses a previous client request token returns the same
	// QueryExecutionId even if the requester doesn't have permission on the tables
	// specified in QueryString . This token is listed as not required because Amazon
	// Web Services SDKs (for example the Amazon Web Services SDK for Java)
	// auto-generate the token for users. If you are not using the Amazon Web Services
	// SDK or the Amazon Web Services CLI, you must provide this token or the action
	// will fail.
	ClientRequestToken *string

	// A list of values for the parameters in a query. The values are applied
	// sequentially to the parameters in the query in the order in which the parameters
	// occur.
	ExecutionParameters []string

	// The database within which the query executes.
	QueryExecutionContext *types.QueryExecutionContext

	// Specifies information about where and how to save the results of the query
	// execution. If the query runs in a workgroup, then workgroup's settings may
	// override query settings. This affects the query results location. The workgroup
	// settings override is specified in EnforceWorkGroupConfiguration (true/false) in
	// the WorkGroupConfiguration. See
	// WorkGroupConfiguration$EnforceWorkGroupConfiguration .
	ResultConfiguration *types.ResultConfiguration

	// Specifies the query result reuse behavior for the query.
	ResultReuseConfiguration *types.ResultReuseConfiguration

	// The name of the workgroup in which the query is being started.
	WorkGroup *string

	noSmithyDocumentSerde
}

type StartQueryExecutionOutput struct {

	// The unique ID of the query that ran as a result of this request.
	QueryExecutionId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationStartQueryExecutionMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpStartQueryExecution{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpStartQueryExecution{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "StartQueryExecution"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addIdempotencyToken_opStartQueryExecutionMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpStartQueryExecutionValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opStartQueryExecution(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

type idempotencyToken_initializeOpStartQueryExecution struct {
	tokenProvider IdempotencyTokenProvider
}

func (*idempotencyToken_initializeOpStartQueryExecution) ID() string {
	return "OperationIdempotencyTokenAutoFill"
}

func (m *idempotencyToken_initializeOpStartQueryExecution) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	if m.tokenProvider == nil {
		return next.HandleInitialize(ctx, in)
	}

	input, ok := in.Parameters.(*StartQueryExecutionInput)
	if !ok {
		return out, metadata, fmt.Errorf("expected middleware input to be of type *StartQueryExecutionInput ")
	}

	if input.ClientRequestToken == nil {
		t, err := m.tokenProvider.GetIdempotencyToken()
		if err != nil {
			return out, metadata, err
		}
		input.ClientRequestToken = &t
	}
	return next.HandleInitialize(ctx, in)
}
func addIdempotencyToken_opStartQueryExecutionMiddleware(stack *middleware.Stack, cfg Options) error {
	return stack.Initialize.Add(&idempotencyToken_initializeOpStartQueryExecution{tokenProvider: cfg.IdempotencyTokenProvider}, middleware.Before)
}

func newServiceMetadataMiddleware_opStartQueryExecution(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "StartQueryExecution",
	}
}
