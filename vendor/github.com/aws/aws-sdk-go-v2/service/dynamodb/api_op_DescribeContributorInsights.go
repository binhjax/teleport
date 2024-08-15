// Code generated by smithy-go-codegen DO NOT EDIT.

package dynamodb

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"time"
)

// Returns information about contributor insights for a given table or global
// secondary index.
func (c *Client) DescribeContributorInsights(ctx context.Context, params *DescribeContributorInsightsInput, optFns ...func(*Options)) (*DescribeContributorInsightsOutput, error) {
	if params == nil {
		params = &DescribeContributorInsightsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeContributorInsights", params, optFns, c.addOperationDescribeContributorInsightsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeContributorInsightsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeContributorInsightsInput struct {

	// The name of the table to describe. You can also provide the Amazon Resource
	// Name (ARN) of the table in this parameter.
	//
	// This member is required.
	TableName *string

	// The name of the global secondary index to describe, if applicable.
	IndexName *string

	noSmithyDocumentSerde
}

type DescribeContributorInsightsOutput struct {

	// List of names of the associated contributor insights rules.
	ContributorInsightsRuleList []string

	// Current status of contributor insights.
	ContributorInsightsStatus types.ContributorInsightsStatus

	// Returns information about the last failure that was encountered. The most
	// common exceptions for a FAILED status are:
	//   - LimitExceededException - Per-account Amazon CloudWatch Contributor Insights
	//   rule limit reached. Please disable Contributor Insights for other tables/indexes
	//   OR disable Contributor Insights rules before retrying.
	//   - AccessDeniedException - Amazon CloudWatch Contributor Insights rules cannot
	//   be modified due to insufficient permissions.
	//   - AccessDeniedException - Failed to create service-linked role for
	//   Contributor Insights due to insufficient permissions.
	//   - InternalServerError - Failed to create Amazon CloudWatch Contributor
	//   Insights rules. Please retry request.
	FailureException *types.FailureException

	// The name of the global secondary index being described.
	IndexName *string

	// Timestamp of the last time the status was changed.
	LastUpdateDateTime *time.Time

	// The name of the table being described.
	TableName *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeContributorInsightsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson10_serializeOpDescribeContributorInsights{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson10_deserializeOpDescribeContributorInsights{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeContributorInsights"); err != nil {
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
	if err = addOpDescribeContributorInsightsValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeContributorInsights(options.Region), middleware.Before); err != nil {
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
	if err = addValidateResponseChecksum(stack, options); err != nil {
		return err
	}
	if err = addAcceptEncodingGzip(stack, options); err != nil {
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

func newServiceMetadataMiddleware_opDescribeContributorInsights(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeContributorInsights",
	}
}
