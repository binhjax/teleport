package security

import (
    i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91 "github.com/microsoft/kiota-abstractions-go/serialization"
)

type MailClusterEvidence struct {
    AlertEvidence
}
// NewMailClusterEvidence instantiates a new MailClusterEvidence and sets the default values.
func NewMailClusterEvidence()(*MailClusterEvidence) {
    m := &MailClusterEvidence{
        AlertEvidence: *NewAlertEvidence(),
    }
    odataTypeValue := "#microsoft.graph.security.mailClusterEvidence"
    m.SetOdataType(&odataTypeValue)
    return m
}
// CreateMailClusterEvidenceFromDiscriminatorValue creates a new instance of the appropriate class based on discriminator value
// returns a Parsable when successful
func CreateMailClusterEvidenceFromDiscriminatorValue(parseNode i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode)(i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.Parsable, error) {
    return NewMailClusterEvidence(), nil
}
// GetClusterBy gets the clusterBy property value. The clustering logic of the emails inside the cluster.
// returns a *string when successful
func (m *MailClusterEvidence) GetClusterBy()(*string) {
    val, err := m.GetBackingStore().Get("clusterBy")
    if err != nil {
        panic(err)
    }
    if val != nil {
        return val.(*string)
    }
    return nil
}
// GetClusterByValue gets the clusterByValue property value. The value utilized to cluster the similar emails.
// returns a *string when successful
func (m *MailClusterEvidence) GetClusterByValue()(*string) {
    val, err := m.GetBackingStore().Get("clusterByValue")
    if err != nil {
        panic(err)
    }
    if val != nil {
        return val.(*string)
    }
    return nil
}
// GetEmailCount gets the emailCount property value. Count of emails in the email cluster.
// returns a *int64 when successful
func (m *MailClusterEvidence) GetEmailCount()(*int64) {
    val, err := m.GetBackingStore().Get("emailCount")
    if err != nil {
        panic(err)
    }
    if val != nil {
        return val.(*int64)
    }
    return nil
}
// GetFieldDeserializers the deserialization information for the current model
// returns a map[string]func(i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode)(error) when successful
func (m *MailClusterEvidence) GetFieldDeserializers()(map[string]func(i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode)(error)) {
    res := m.AlertEvidence.GetFieldDeserializers()
    res["clusterBy"] = func (n i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode) error {
        val, err := n.GetStringValue()
        if err != nil {
            return err
        }
        if val != nil {
            m.SetClusterBy(val)
        }
        return nil
    }
    res["clusterByValue"] = func (n i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode) error {
        val, err := n.GetStringValue()
        if err != nil {
            return err
        }
        if val != nil {
            m.SetClusterByValue(val)
        }
        return nil
    }
    res["emailCount"] = func (n i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode) error {
        val, err := n.GetInt64Value()
        if err != nil {
            return err
        }
        if val != nil {
            m.SetEmailCount(val)
        }
        return nil
    }
    res["networkMessageIds"] = func (n i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode) error {
        val, err := n.GetCollectionOfPrimitiveValues("string")
        if err != nil {
            return err
        }
        if val != nil {
            res := make([]string, len(val))
            for i, v := range val {
                if v != nil {
                    res[i] = *(v.(*string))
                }
            }
            m.SetNetworkMessageIds(res)
        }
        return nil
    }
    res["query"] = func (n i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode) error {
        val, err := n.GetStringValue()
        if err != nil {
            return err
        }
        if val != nil {
            m.SetQuery(val)
        }
        return nil
    }
    res["urn"] = func (n i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.ParseNode) error {
        val, err := n.GetStringValue()
        if err != nil {
            return err
        }
        if val != nil {
            m.SetUrn(val)
        }
        return nil
    }
    return res
}
// GetNetworkMessageIds gets the networkMessageIds property value. Unique identifiers for the emails in the cluster, generated by Microsoft 365.
// returns a []string when successful
func (m *MailClusterEvidence) GetNetworkMessageIds()([]string) {
    val, err := m.GetBackingStore().Get("networkMessageIds")
    if err != nil {
        panic(err)
    }
    if val != nil {
        return val.([]string)
    }
    return nil
}
// GetQuery gets the query property value. The query used to identify the email cluster.
// returns a *string when successful
func (m *MailClusterEvidence) GetQuery()(*string) {
    val, err := m.GetBackingStore().Get("query")
    if err != nil {
        panic(err)
    }
    if val != nil {
        return val.(*string)
    }
    return nil
}
// GetUrn gets the urn property value. Uniform resource name (URN) of the automated investigation where the cluster was identified.
// returns a *string when successful
func (m *MailClusterEvidence) GetUrn()(*string) {
    val, err := m.GetBackingStore().Get("urn")
    if err != nil {
        panic(err)
    }
    if val != nil {
        return val.(*string)
    }
    return nil
}
// Serialize serializes information the current object
func (m *MailClusterEvidence) Serialize(writer i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.SerializationWriter)(error) {
    err := m.AlertEvidence.Serialize(writer)
    if err != nil {
        return err
    }
    {
        err = writer.WriteStringValue("clusterBy", m.GetClusterBy())
        if err != nil {
            return err
        }
    }
    {
        err = writer.WriteStringValue("clusterByValue", m.GetClusterByValue())
        if err != nil {
            return err
        }
    }
    {
        err = writer.WriteInt64Value("emailCount", m.GetEmailCount())
        if err != nil {
            return err
        }
    }
    if m.GetNetworkMessageIds() != nil {
        err = writer.WriteCollectionOfStringValues("networkMessageIds", m.GetNetworkMessageIds())
        if err != nil {
            return err
        }
    }
    {
        err = writer.WriteStringValue("query", m.GetQuery())
        if err != nil {
            return err
        }
    }
    {
        err = writer.WriteStringValue("urn", m.GetUrn())
        if err != nil {
            return err
        }
    }
    return nil
}
// SetClusterBy sets the clusterBy property value. The clustering logic of the emails inside the cluster.
func (m *MailClusterEvidence) SetClusterBy(value *string)() {
    err := m.GetBackingStore().Set("clusterBy", value)
    if err != nil {
        panic(err)
    }
}
// SetClusterByValue sets the clusterByValue property value. The value utilized to cluster the similar emails.
func (m *MailClusterEvidence) SetClusterByValue(value *string)() {
    err := m.GetBackingStore().Set("clusterByValue", value)
    if err != nil {
        panic(err)
    }
}
// SetEmailCount sets the emailCount property value. Count of emails in the email cluster.
func (m *MailClusterEvidence) SetEmailCount(value *int64)() {
    err := m.GetBackingStore().Set("emailCount", value)
    if err != nil {
        panic(err)
    }
}
// SetNetworkMessageIds sets the networkMessageIds property value. Unique identifiers for the emails in the cluster, generated by Microsoft 365.
func (m *MailClusterEvidence) SetNetworkMessageIds(value []string)() {
    err := m.GetBackingStore().Set("networkMessageIds", value)
    if err != nil {
        panic(err)
    }
}
// SetQuery sets the query property value. The query used to identify the email cluster.
func (m *MailClusterEvidence) SetQuery(value *string)() {
    err := m.GetBackingStore().Set("query", value)
    if err != nil {
        panic(err)
    }
}
// SetUrn sets the urn property value. Uniform resource name (URN) of the automated investigation where the cluster was identified.
func (m *MailClusterEvidence) SetUrn(value *string)() {
    err := m.GetBackingStore().Set("urn", value)
    if err != nil {
        panic(err)
    }
}
type MailClusterEvidenceable interface {
    AlertEvidenceable
    i878a80d2330e89d26896388a3f487eef27b0a0e6c010c493bf80be1452208f91.Parsable
    GetClusterBy()(*string)
    GetClusterByValue()(*string)
    GetEmailCount()(*int64)
    GetNetworkMessageIds()([]string)
    GetQuery()(*string)
    GetUrn()(*string)
    SetClusterBy(value *string)()
    SetClusterByValue(value *string)()
    SetEmailCount(value *int64)()
    SetNetworkMessageIds(value []string)()
    SetQuery(value *string)()
    SetUrn(value *string)()
}
