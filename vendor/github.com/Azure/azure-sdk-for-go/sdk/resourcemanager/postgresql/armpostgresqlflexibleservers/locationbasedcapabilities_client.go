//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.
// DO NOT EDIT.

package armpostgresqlflexibleservers

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// LocationBasedCapabilitiesClient contains the methods for the LocationBasedCapabilities group.
// Don't use this type directly, use NewLocationBasedCapabilitiesClient() instead.
type LocationBasedCapabilitiesClient struct {
	host           string
	subscriptionID string
	pl             runtime.Pipeline
}

// NewLocationBasedCapabilitiesClient creates a new instance of LocationBasedCapabilitiesClient with the specified values.
// subscriptionID - The ID of the target subscription.
// credential - used to authorize requests. Usually a credential from azidentity.
// options - pass nil to accept the default values.
func NewLocationBasedCapabilitiesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*LocationBasedCapabilitiesClient, error) {
	if options == nil {
		options = &arm.ClientOptions{}
	}
	ep := cloud.AzurePublic.Services[cloud.ResourceManager].Endpoint
	if c, ok := options.Cloud.Services[cloud.ResourceManager]; ok {
		ep = c.Endpoint
	}
	pl, err := armruntime.NewPipeline(moduleName, moduleVersion, credential, runtime.PipelineOptions{}, options)
	if err != nil {
		return nil, err
	}
	client := &LocationBasedCapabilitiesClient{
		subscriptionID: subscriptionID,
		host:           ep,
		pl:             pl,
	}
	return client, nil
}

// NewExecutePager - Get capabilities at specified location in a given subscription.
// If the operation fails it returns an *azcore.ResponseError type.
// Generated from API version 2021-06-01
// locationName - The name of the location.
// options - LocationBasedCapabilitiesClientExecuteOptions contains the optional parameters for the LocationBasedCapabilitiesClient.Execute
// method.
func (client *LocationBasedCapabilitiesClient) NewExecutePager(locationName string, options *LocationBasedCapabilitiesClientExecuteOptions) *runtime.Pager[LocationBasedCapabilitiesClientExecuteResponse] {
	return runtime.NewPager(runtime.PagingHandler[LocationBasedCapabilitiesClientExecuteResponse]{
		More: func(page LocationBasedCapabilitiesClientExecuteResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *LocationBasedCapabilitiesClientExecuteResponse) (LocationBasedCapabilitiesClientExecuteResponse, error) {
			var req *policy.Request
			var err error
			if page == nil {
				req, err = client.executeCreateRequest(ctx, locationName, options)
			} else {
				req, err = runtime.NewRequest(ctx, http.MethodGet, *page.NextLink)
			}
			if err != nil {
				return LocationBasedCapabilitiesClientExecuteResponse{}, err
			}
			resp, err := client.pl.Do(req)
			if err != nil {
				return LocationBasedCapabilitiesClientExecuteResponse{}, err
			}
			if !runtime.HasStatusCode(resp, http.StatusOK) {
				return LocationBasedCapabilitiesClientExecuteResponse{}, runtime.NewResponseError(resp)
			}
			return client.executeHandleResponse(resp)
		},
	})
}

// executeCreateRequest creates the Execute request.
func (client *LocationBasedCapabilitiesClient) executeCreateRequest(ctx context.Context, locationName string, options *LocationBasedCapabilitiesClientExecuteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/locations/{locationName}/capabilities"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if locationName == "" {
		return nil, errors.New("parameter locationName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{locationName}", url.PathEscape(locationName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// executeHandleResponse handles the Execute response.
func (client *LocationBasedCapabilitiesClient) executeHandleResponse(resp *http.Response) (LocationBasedCapabilitiesClientExecuteResponse, error) {
	result := LocationBasedCapabilitiesClientExecuteResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.CapabilitiesListResult); err != nil {
		return LocationBasedCapabilitiesClientExecuteResponse{}, err
	}
	return result, nil
}
