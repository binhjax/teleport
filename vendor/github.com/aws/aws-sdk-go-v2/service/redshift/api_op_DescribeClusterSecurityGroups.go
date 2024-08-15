// Code generated by smithy-go-codegen DO NOT EDIT.

package redshift

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Returns information about Amazon Redshift security groups. If the name of a
// security group is specified, the response will contain only information about
// only that security group. For information about managing security groups, go to
// Amazon Redshift Cluster Security Groups (https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-security-groups.html)
// in the Amazon Redshift Cluster Management Guide. If you specify both tag keys
// and tag values in the same request, Amazon Redshift returns all security groups
// that match any combination of the specified keys and values. For example, if you
// have owner and environment for tag keys, and admin and test for tag values, all
// security groups that have any combination of those values are returned. If both
// tag keys and values are omitted from the request, security groups are returned
// regardless of whether they have tag keys or values associated with them.
func (c *Client) DescribeClusterSecurityGroups(ctx context.Context, params *DescribeClusterSecurityGroupsInput, optFns ...func(*Options)) (*DescribeClusterSecurityGroupsOutput, error) {
	if params == nil {
		params = &DescribeClusterSecurityGroupsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeClusterSecurityGroups", params, optFns, c.addOperationDescribeClusterSecurityGroupsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeClusterSecurityGroupsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeClusterSecurityGroupsInput struct {

	// The name of a cluster security group for which you are requesting details. You
	// must specify either the Marker parameter or a ClusterSecurityGroupName
	// parameter, but not both. Example: securitygroup1
	ClusterSecurityGroupName *string

	// An optional parameter that specifies the starting point to return a set of
	// response records. When the results of a DescribeClusterSecurityGroups request
	// exceed the value specified in MaxRecords , Amazon Web Services returns a value
	// in the Marker field of the response. You can retrieve the next set of response
	// records by providing the returned marker value in the Marker parameter and
	// retrying the request. Constraints: You must specify either the
	// ClusterSecurityGroupName parameter or the Marker parameter, but not both.
	Marker *string

	// The maximum number of response records to return in each call. If the number of
	// remaining response records exceeds the specified MaxRecords value, a value is
	// returned in a marker field of the response. You can retrieve the next set of
	// records by retrying the command with the returned marker value. Default: 100
	// Constraints: minimum 20, maximum 100.
	MaxRecords *int32

	// A tag key or keys for which you want to return all matching cluster security
	// groups that are associated with the specified key or keys. For example, suppose
	// that you have security groups that are tagged with keys called owner and
	// environment . If you specify both of these tag keys in the request, Amazon
	// Redshift returns a response with the security groups that have either or both of
	// these tag keys associated with them.
	TagKeys []string

	// A tag value or values for which you want to return all matching cluster
	// security groups that are associated with the specified tag value or values. For
	// example, suppose that you have security groups that are tagged with values
	// called admin and test . If you specify both of these tag values in the request,
	// Amazon Redshift returns a response with the security groups that have either or
	// both of these tag values associated with them.
	TagValues []string

	noSmithyDocumentSerde
}

type DescribeClusterSecurityGroupsOutput struct {

	// A list of ClusterSecurityGroup instances.
	ClusterSecurityGroups []types.ClusterSecurityGroup

	// A value that indicates the starting point for the next set of response records
	// in a subsequent request. If a value is returned in a response, you can retrieve
	// the next set of records by providing this returned marker value in the Marker
	// parameter and retrying the command. If the Marker field is empty, all response
	// records have been retrieved for the request.
	Marker *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeClusterSecurityGroupsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpDescribeClusterSecurityGroups{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpDescribeClusterSecurityGroups{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeClusterSecurityGroups"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeClusterSecurityGroups(options.Region), middleware.Before); err != nil {
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

// DescribeClusterSecurityGroupsAPIClient is a client that implements the
// DescribeClusterSecurityGroups operation.
type DescribeClusterSecurityGroupsAPIClient interface {
	DescribeClusterSecurityGroups(context.Context, *DescribeClusterSecurityGroupsInput, ...func(*Options)) (*DescribeClusterSecurityGroupsOutput, error)
}

var _ DescribeClusterSecurityGroupsAPIClient = (*Client)(nil)

// DescribeClusterSecurityGroupsPaginatorOptions is the paginator options for
// DescribeClusterSecurityGroups
type DescribeClusterSecurityGroupsPaginatorOptions struct {
	// The maximum number of response records to return in each call. If the number of
	// remaining response records exceeds the specified MaxRecords value, a value is
	// returned in a marker field of the response. You can retrieve the next set of
	// records by retrying the command with the returned marker value. Default: 100
	// Constraints: minimum 20, maximum 100.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeClusterSecurityGroupsPaginator is a paginator for
// DescribeClusterSecurityGroups
type DescribeClusterSecurityGroupsPaginator struct {
	options   DescribeClusterSecurityGroupsPaginatorOptions
	client    DescribeClusterSecurityGroupsAPIClient
	params    *DescribeClusterSecurityGroupsInput
	nextToken *string
	firstPage bool
}

// NewDescribeClusterSecurityGroupsPaginator returns a new
// DescribeClusterSecurityGroupsPaginator
func NewDescribeClusterSecurityGroupsPaginator(client DescribeClusterSecurityGroupsAPIClient, params *DescribeClusterSecurityGroupsInput, optFns ...func(*DescribeClusterSecurityGroupsPaginatorOptions)) *DescribeClusterSecurityGroupsPaginator {
	if params == nil {
		params = &DescribeClusterSecurityGroupsInput{}
	}

	options := DescribeClusterSecurityGroupsPaginatorOptions{}
	if params.MaxRecords != nil {
		options.Limit = *params.MaxRecords
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeClusterSecurityGroupsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.Marker,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeClusterSecurityGroupsPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeClusterSecurityGroups page.
func (p *DescribeClusterSecurityGroupsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeClusterSecurityGroupsOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.Marker = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxRecords = limit

	result, err := p.client.DescribeClusterSecurityGroups(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.Marker

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opDescribeClusterSecurityGroups(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeClusterSecurityGroups",
	}
}
