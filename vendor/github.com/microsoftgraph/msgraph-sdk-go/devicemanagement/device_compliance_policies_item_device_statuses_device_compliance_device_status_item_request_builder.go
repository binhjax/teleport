package devicemanagement

import (
    "context"
    i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f "github.com/microsoft/kiota-abstractions-go"
    iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242 "github.com/microsoftgraph/msgraph-sdk-go/models"
    ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a "github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

// DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder provides operations to manage the deviceStatuses property of the microsoft.graph.deviceCompliancePolicy entity.
type DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder struct {
    i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.BaseRequestBuilder
}
// DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderDeleteRequestConfiguration configuration for the request such as headers, query parameters, and middleware options.
type DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderDeleteRequestConfiguration struct {
    // Request headers
    Headers *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestHeaders
    // Request options
    Options []i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestOption
}
// DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetQueryParameters list of DeviceComplianceDeviceStatus.
type DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetQueryParameters struct {
    // Expand related entities
    Expand []string `uriparametername:"%24expand"`
    // Select properties to be returned
    Select []string `uriparametername:"%24select"`
}
// DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetRequestConfiguration configuration for the request such as headers, query parameters, and middleware options.
type DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetRequestConfiguration struct {
    // Request headers
    Headers *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestHeaders
    // Request options
    Options []i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestOption
    // Request query parameters
    QueryParameters *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetQueryParameters
}
// DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderPatchRequestConfiguration configuration for the request such as headers, query parameters, and middleware options.
type DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderPatchRequestConfiguration struct {
    // Request headers
    Headers *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestHeaders
    // Request options
    Options []i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestOption
}
// NewDeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderInternal instantiates a new DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder and sets the default values.
func NewDeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderInternal(pathParameters map[string]string, requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter)(*DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) {
    m := &DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder{
        BaseRequestBuilder: *i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.NewBaseRequestBuilder(requestAdapter, "{+baseurl}/deviceManagement/deviceCompliancePolicies/{deviceCompliancePolicy%2Did}/deviceStatuses/{deviceComplianceDeviceStatus%2Did}{?%24expand,%24select}", pathParameters),
    }
    return m
}
// NewDeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder instantiates a new DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder and sets the default values.
func NewDeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder(rawUrl string, requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter)(*DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) {
    urlParams := make(map[string]string)
    urlParams["request-raw-url"] = rawUrl
    return NewDeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderInternal(urlParams, requestAdapter)
}
// Delete delete navigation property deviceStatuses for deviceManagement
// returns a ODataError error when the service returns a 4XX or 5XX status code
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) Delete(ctx context.Context, requestConfiguration *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderDeleteRequestConfiguration)(error) {
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
// Get list of DeviceComplianceDeviceStatus.
// returns a DeviceComplianceDeviceStatusable when successful
// returns a ODataError error when the service returns a 4XX or 5XX status code
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) Get(ctx context.Context, requestConfiguration *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetRequestConfiguration)(iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.DeviceComplianceDeviceStatusable, error) {
    requestInfo, err := m.ToGetRequestInformation(ctx, requestConfiguration);
    if err != nil {
        return nil, err
    }
    errorMapping := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.ErrorMappings {
        "XXX": ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a.CreateODataErrorFromDiscriminatorValue,
    }
    res, err := m.BaseRequestBuilder.RequestAdapter.Send(ctx, requestInfo, iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.CreateDeviceComplianceDeviceStatusFromDiscriminatorValue, errorMapping)
    if err != nil {
        return nil, err
    }
    if res == nil {
        return nil, nil
    }
    return res.(iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.DeviceComplianceDeviceStatusable), nil
}
// Patch update the navigation property deviceStatuses in deviceManagement
// returns a DeviceComplianceDeviceStatusable when successful
// returns a ODataError error when the service returns a 4XX or 5XX status code
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) Patch(ctx context.Context, body iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.DeviceComplianceDeviceStatusable, requestConfiguration *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderPatchRequestConfiguration)(iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.DeviceComplianceDeviceStatusable, error) {
    requestInfo, err := m.ToPatchRequestInformation(ctx, body, requestConfiguration);
    if err != nil {
        return nil, err
    }
    errorMapping := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.ErrorMappings {
        "XXX": ia572726a95efa92ddd544552cd950653dc691023836923576b2f4bf716cf204a.CreateODataErrorFromDiscriminatorValue,
    }
    res, err := m.BaseRequestBuilder.RequestAdapter.Send(ctx, requestInfo, iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.CreateDeviceComplianceDeviceStatusFromDiscriminatorValue, errorMapping)
    if err != nil {
        return nil, err
    }
    if res == nil {
        return nil, nil
    }
    return res.(iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.DeviceComplianceDeviceStatusable), nil
}
// ToDeleteRequestInformation delete navigation property deviceStatuses for deviceManagement
// returns a *RequestInformation when successful
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) ToDeleteRequestInformation(ctx context.Context, requestConfiguration *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderDeleteRequestConfiguration)(*i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestInformation, error) {
    requestInfo := i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.NewRequestInformationWithMethodAndUrlTemplateAndPathParameters(i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.DELETE, m.BaseRequestBuilder.UrlTemplate, m.BaseRequestBuilder.PathParameters)
    if requestConfiguration != nil {
        requestInfo.Headers.AddAll(requestConfiguration.Headers)
        requestInfo.AddRequestOptions(requestConfiguration.Options)
    }
    requestInfo.Headers.TryAdd("Accept", "application/json")
    return requestInfo, nil
}
// ToGetRequestInformation list of DeviceComplianceDeviceStatus.
// returns a *RequestInformation when successful
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) ToGetRequestInformation(ctx context.Context, requestConfiguration *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderGetRequestConfiguration)(*i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestInformation, error) {
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
// ToPatchRequestInformation update the navigation property deviceStatuses in deviceManagement
// returns a *RequestInformation when successful
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) ToPatchRequestInformation(ctx context.Context, body iadcd81124412c61e647227ecfc4449d8bba17de0380ddda76f641a29edf2b242.DeviceComplianceDeviceStatusable, requestConfiguration *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilderPatchRequestConfiguration)(*i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestInformation, error) {
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
// returns a *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder when successful
func (m *DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) WithUrl(rawUrl string)(*DeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder) {
    return NewDeviceCompliancePoliciesItemDeviceStatusesDeviceComplianceDeviceStatusItemRequestBuilder(rawUrl, m.BaseRequestBuilder.RequestAdapter);
}
