// Code generated by smithy-go-codegen DO NOT EDIT.

package ecs

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Returns a list of existing clusters.
func (c *Client) ListClusters(ctx context.Context, params *ListClustersInput, optFns ...func(*Options)) (*ListClustersOutput, error) {
	if params == nil {
		params = &ListClustersInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ListClusters", params, optFns, c.addOperationListClustersMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ListClustersOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ListClustersInput struct {

	// The maximum number of cluster results that ListClusters returned in paginated
	// output. When this parameter is used, ListClusters only returns maxResults
	// results in a single page along with a nextToken response element. The remaining
	// results of the initial request can be seen by sending another ListClusters
	// request with the returned nextToken value. This value can be between 1 and 100.
	// If this parameter isn't used, then ListClusters returns up to 100 results and a
	// nextToken value if applicable.
	MaxResults *int32

	// The nextToken value returned from a ListClusters request indicating that more
	// results are available to fulfill the request and further calls are needed. If
	// maxResults was provided, it's possible the number of results to be fewer than
	// maxResults . This token should be treated as an opaque identifier that is only
	// used to retrieve the next items in a list and not for other programmatic
	// purposes.
	NextToken *string

	noSmithyDocumentSerde
}

type ListClustersOutput struct {

	// The list of full Amazon Resource Name (ARN) entries for each cluster that's
	// associated with your account.
	ClusterArns []string

	// The nextToken value to include in a future ListClusters request. When the
	// results of a ListClusters request exceed maxResults , this value can be used to
	// retrieve the next page of results. This value is null when there are no more
	// results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationListClustersMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpListClusters{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpListClusters{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "ListClusters"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opListClusters(options.Region), middleware.Before); err != nil {
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

// ListClustersAPIClient is a client that implements the ListClusters operation.
type ListClustersAPIClient interface {
	ListClusters(context.Context, *ListClustersInput, ...func(*Options)) (*ListClustersOutput, error)
}

var _ ListClustersAPIClient = (*Client)(nil)

// ListClustersPaginatorOptions is the paginator options for ListClusters
type ListClustersPaginatorOptions struct {
	// The maximum number of cluster results that ListClusters returned in paginated
	// output. When this parameter is used, ListClusters only returns maxResults
	// results in a single page along with a nextToken response element. The remaining
	// results of the initial request can be seen by sending another ListClusters
	// request with the returned nextToken value. This value can be between 1 and 100.
	// If this parameter isn't used, then ListClusters returns up to 100 results and a
	// nextToken value if applicable.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// ListClustersPaginator is a paginator for ListClusters
type ListClustersPaginator struct {
	options   ListClustersPaginatorOptions
	client    ListClustersAPIClient
	params    *ListClustersInput
	nextToken *string
	firstPage bool
}

// NewListClustersPaginator returns a new ListClustersPaginator
func NewListClustersPaginator(client ListClustersAPIClient, params *ListClustersInput, optFns ...func(*ListClustersPaginatorOptions)) *ListClustersPaginator {
	if params == nil {
		params = &ListClustersInput{}
	}

	options := ListClustersPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &ListClustersPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *ListClustersPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next ListClusters page.
func (p *ListClustersPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*ListClustersOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.ListClusters(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opListClusters(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "ListClusters",
	}
}
