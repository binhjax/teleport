package sites

import (
    i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91 "github.com/microsoft/kiota-abstractions-go/serialization"
)

// Deprecated: This class is obsolete. Use ItemGetApplicableContentTypesForListWithListIdGetResponseable instead.
type ItemGetApplicableContentTypesForListWithListIdResponse struct {
    ItemGetApplicableContentTypesForListWithListIdGetResponse
}
// NewItemGetApplicableContentTypesForListWithListIdResponse instantiates a new ItemGetApplicableContentTypesForListWithListIdResponse and sets the default values.
func NewItemGetApplicableContentTypesForListWithListIdResponse()(*ItemGetApplicableContentTypesForListWithListIdResponse) {
    m := &ItemGetApplicableContentTypesForListWithListIdResponse{
        ItemGetApplicableContentTypesForListWithListIdGetResponse: *NewItemGetApplicableContentTypesForListWithListIdGetResponse(),
    }
    return m
}
// CreateItemGetApplicableContentTypesForListWithListIdResponseFromDiscriminatorValue creates a new instance of the appropriate class based on discriminator value
// returns a Parsable when successful
func CreateItemGetApplicableContentTypesForListWithListIdResponseFromDiscriminatorValue(parseNode i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode)(i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.Parsable, error) {
    return NewItemGetApplicableContentTypesForListWithListIdResponse(), nil
}
// Deprecated: This class is obsolete. Use ItemGetApplicableContentTypesForListWithListIdGetResponseable instead.
type ItemGetApplicableContentTypesForListWithListIdResponseable interface {
    ItemGetApplicableContentTypesForListWithListIdGetResponseable
    i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.Parsable
}
