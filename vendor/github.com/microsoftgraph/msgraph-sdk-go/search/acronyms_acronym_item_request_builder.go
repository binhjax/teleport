package search

import (
    "context"
    i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f "github.com/microsoft/kiota-abstractions-go"
    i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e "github.com/microsoftgraph/msgraph-sdk-go/models/search"
    ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a "github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

// AcronymsAcronymItemRequestBuilder provides operations to manage the acronyms property of the microsoft.graph.searchEntity entity.
type AcronymsAcronymItemRequestBuilder struct {
    i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.BaseRequestBuilder
}
// AcronymsAcronymItemRequestBuilderDeleteRequestConfiguration configuration for the request such as headers, query parameters, and middleware options.
type AcronymsAcronymItemRequestBuilderDeleteRequestConfiguration struct {
    // Request headers
    Headers *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestHeaders
    // Request options
    Options []i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestOption
}
// AcronymsAcronymItemRequestBuilderGetQueryParameters administrative answer in Microsoft Search results to define common acronyms in an organization.
type AcronymsAcronymItemRequestBuilderGetQueryParameters struct {
    // Expand related entities
    Expand []string `uriparametername:"%24expand"`
    // Select properties to be returned
    Select []string `uriparametername:"%24select"`
}
// AcronymsAcronymItemRequestBuilderGetRequestConfiguration configuration for the request such as headers, query parameters, and middleware options.
type AcronymsAcronymItemRequestBuilderGetRequestConfiguration struct {
    // Request headers
    Headers *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestHeaders
    // Request options
    Options []i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestOption
    // Request query parameters
    QueryParameters *AcronymsAcronymItemRequestBuilderGetQueryParameters
}
// AcronymsAcronymItemRequestBuilderPatchRequestConfiguration configuration for the request such as headers, query parameters, and middleware options.
type AcronymsAcronymItemRequestBuilderPatchRequestConfiguration struct {
    // Request headers
    Headers *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestHeaders
    // Request options
    Options []i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestOption
}
// NewAcronymsAcronymItemRequestBuilderInternal instantiates a new AcronymsAcronymItemRequestBuilder and sets the default values.
func NewAcronymsAcronymItemRequestBuilderInternal(pathParameters map[string]string, requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter)(*AcronymsAcronymItemRequestBuilder) {
    m := &AcronymsAcronymItemRequestBuilder{
        BaseRequestBuilder: *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.NewBaseRequestBuilder(requestAdapter, "{+baseurl}/search/acronyms/{acronym%2Did}{?%24expand,%24select}", pathParameters),
    }
    return m
}
// NewAcronymsAcronymItemRequestBuilder instantiates a new AcronymsAcronymItemRequestBuilder and sets the default values.
func NewAcronymsAcronymItemRequestBuilder(rawUrl string, requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter)(*AcronymsAcronymItemRequestBuilder) {
    urlParams := make(map[string]string)
    urlParams["request-raw-url"] = rawUrl
    return NewAcronymsAcronymItemRequestBuilderInternal(urlParams, requestAdapter)
}
// Delete delete navigation property acronyms for search
// returns a ODataError error when the service returns a 4XX or 5XX status code
func (m *AcronymsAcronymItemRequestBuilder) Delete(ctx context.Context, requestConfiguration *AcronymsAcronymItemRequestBuilderDeleteRequestConfiguration)(error) {
    requestInfo, err := m.ToDeleteRequestInformation(ctx, requestConfiguration);
    if err != nil {
        return err
    }
    errorMapping := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.ErrorMappings {
        "XXX": ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a.CreateODataErrorFromDiscriminatorValue,
    }
    err = m.BaseRequestBuilder.RequestAdapter.SendNoContent(ctx, requestInfo, errorMapping)
    if err != nil {
        return err
    }
    return nil
}
// Get administrative answer in Microsoft Search results to define common acronyms in an organization.
// returns a Acronymable when successful
// returns a ODataError error when the service returns a 4XX or 5XX status code
func (m *AcronymsAcronymItemRequestBuilder) Get(ctx context.Context, requestConfiguration *AcronymsAcronymItemRequestBuilderGetRequestConfiguration)(i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.Acronymable, error) {
    requestInfo, err := m.ToGetRequestInformation(ctx, requestConfiguration);
    if err != nil {
        return nil, err
    }
    errorMapping := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.ErrorMappings {
        "XXX": ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a.CreateODataErrorFromDiscriminatorValue,
    }
    res, err := m.BaseRequestBuilder.RequestAdapter.Send(ctx, requestInfo, i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.CreateAcronymFromDiscriminatorValue, errorMapping)
    if err != nil {
        return nil, err
    }
    if res == nil {
        return nil, nil
    }
    return res.(i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.Acronymable), nil
}
// Patch update the navigation property acronyms in search
// returns a Acronymable when successful
// returns a ODataError error when the service returns a 4XX or 5XX status code
func (m *AcronymsAcronymItemRequestBuilder) Patch(ctx context.Context, body i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.Acronymable, requestConfiguration *AcronymsAcronymItemRequestBuilderPatchRequestConfiguration)(i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.Acronymable, error) {
    requestInfo, err := m.ToPatchRequestInformation(ctx, body, requestConfiguration);
    if err != nil {
        return nil, err
    }
    errorMapping := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.ErrorMappings {
        "XXX": ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a.CreateODataErrorFromDiscriminatorValue,
    }
    res, err := m.BaseRequestBuilder.RequestAdapter.Send(ctx, requestInfo, i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.CreateAcronymFromDiscriminatorValue, errorMapping)
    if err != nil {
        return nil, err
    }
    if res == nil {
        return nil, nil
    }
    return res.(i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.Acronymable), nil
}
// ToDeleteRequestInformation delete navigation property acronyms for search
// returns a *RequestInformation when successful
func (m *AcronymsAcronymItemRequestBuilder) ToDeleteRequestInformation(ctx context.Context, requestConfiguration *AcronymsAcronymItemRequestBuilderDeleteRequestConfiguration)(*i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestInformation, error) {
    requestInfo := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.NewRequestInformationWithMethodAndUrlTemplateAndPathParameters(i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.DELETE, m.BaseRequestBuilder.UrlTemplate, m.BaseRequestBuilder.PathParameters)
    if requestConfiguration != nil {
        requestInfo.Headers.AddAll(requestConfiguration.Headers)
        requestInfo.AddRequestOptions(requestConfiguration.Options)
    }
    requestInfo.Headers.TryAdd("Accept", "application/json")
    return requestInfo, nil
}
// ToGetRequestInformation administrative answer in Microsoft Search results to define common acronyms in an organization.
// returns a *RequestInformation when successful
func (m *AcronymsAcronymItemRequestBuilder) ToGetRequestInformation(ctx context.Context, requestConfiguration *AcronymsAcronymItemRequestBuilderGetRequestConfiguration)(*i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestInformation, error) {
    requestInfo := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.NewRequestInformationWithMethodAndUrlTemplateAndPathParameters(i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.GET, m.BaseRequestBuilder.UrlTemplate, m.BaseRequestBuilder.PathParameters)
    if requestConfiguration != nil {
        if requestConfiguration.QueryParameters != nil {
            requestInfo.AddQueryParameters(*(requestConfiguration.QueryParameters))
        }
        requestInfo.Headers.AddAll(requestConfiguration.Headers)
        requestInfo.AddRequestOptions(requestConfiguration.Options)
    }
    requestInfo.Headers.TryAdd("Accept", "application/json")
    return requestInfo, nil
}
// ToPatchRequestInformation update the navigation property acronyms in search
// returns a *RequestInformation when successful
func (m *AcronymsAcronymItemRequestBuilder) ToPatchRequestInformation(ctx context.Context, body i517b35a40b7cc3c50a0c7990c48f2ec92f4c4d36a97445a2aebfdc3c0071c22e.Acronymable, requestConfiguration *AcronymsAcronymItemRequestBuilderPatchRequestConfiguration)(*i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestInformation, error) {
    requestInfo := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.NewRequestInformationWithMethodAndUrlTemplateAndPathParameters(i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.PATCH, m.BaseRequestBuilder.UrlTemplate, m.BaseRequestBuilder.PathParameters)
    if requestConfiguration != nil {
        requestInfo.Headers.AddAll(requestConfiguration.Headers)
        requestInfo.AddRequestOptions(requestConfiguration.Options)
    }
    requestInfo.Headers.TryAdd("Accept", "application/json")
    err := requestInfo.SetContentFromParsable(ctx, m.BaseRequestBuilder.RequestAdapter, "application/json", body)
    if err != nil {
        return nil, err
    }
    return requestInfo, nil
}
// WithUrl returns a request builder with the provided arbitrary URL. Using this method means any other path or query parameters are ignored.
// returns a *AcronymsAcronymItemRequestBuilder when successful
func (m *AcronymsAcronymItemRequestBuilder) WithUrl(rawUrl string)(*AcronymsAcronymItemRequestBuilder) {
    return NewAcronymsAcronymItemRequestBuilder(rawUrl, m.BaseRequestBuilder.RequestAdapter);
}
