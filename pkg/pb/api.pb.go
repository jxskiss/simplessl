// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.15.8
// source: api.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Certificate_Type int32

const (
	Certificate_UNKNOWN        Certificate_Type = 0
	Certificate_ALPN           Certificate_Type = 1
	Certificate_SELF_SIGNED    Certificate_Type = 2
	Certificate_MANAGED        Certificate_Type = 3
	Certificate_ACME_ON_DEMAND Certificate_Type = 11
	Certificate_ACME_NAMED     Certificate_Type = 12
)

// Enum value maps for Certificate_Type.
var (
	Certificate_Type_name = map[int32]string{
		0:  "UNKNOWN",
		1:  "ALPN",
		2:  "SELF_SIGNED",
		3:  "MANAGED",
		11: "ACME_ON_DEMAND",
		12: "ACME_NAMED",
	}
	Certificate_Type_value = map[string]int32{
		"UNKNOWN":        0,
		"ALPN":           1,
		"SELF_SIGNED":    2,
		"MANAGED":        3,
		"ACME_ON_DEMAND": 11,
		"ACME_NAMED":     12,
	}
)

func (x Certificate_Type) Enum() *Certificate_Type {
	p := new(Certificate_Type)
	*p = x
	return p
}

func (x Certificate_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Certificate_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_api_proto_enumTypes[0].Descriptor()
}

func (Certificate_Type) Type() protoreflect.EnumType {
	return &file_api_proto_enumTypes[0]
}

func (x Certificate_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Certificate_Type.Descriptor instead.
func (Certificate_Type) EnumDescriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{0, 0}
}

type Certificate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type            int32  `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	PubKey          string `protobuf:"bytes,2,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
	PrivKey         string `protobuf:"bytes,3,opt,name=priv_key,json=privKey,proto3" json:"priv_key,omitempty"`
	Fp              string `protobuf:"bytes,4,opt,name=fp,proto3" json:"fp,omitempty"`
	NotBeforeSec    int64  `protobuf:"varint,5,opt,name=not_before_sec,json=notBeforeSec,proto3" json:"not_before_sec,omitempty"`
	NotAfterSec     int64  `protobuf:"varint,6,opt,name=not_after_sec,json=notAfterSec,proto3" json:"not_after_sec,omitempty"`
	TtlSec          int64  `protobuf:"varint,7,opt,name=ttl_sec,json=ttlSec,proto3" json:"ttl_sec,omitempty"`
	HasOcspStapling bool   `protobuf:"varint,8,opt,name=has_ocsp_stapling,json=hasOcspStapling,proto3" json:"has_ocsp_stapling,omitempty"`
}

func (x *Certificate) Reset() {
	*x = Certificate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Certificate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Certificate) ProtoMessage() {}

func (x *Certificate) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Certificate.ProtoReflect.Descriptor instead.
func (*Certificate) Descriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{0}
}

func (x *Certificate) GetType() int32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *Certificate) GetPubKey() string {
	if x != nil {
		return x.PubKey
	}
	return ""
}

func (x *Certificate) GetPrivKey() string {
	if x != nil {
		return x.PrivKey
	}
	return ""
}

func (x *Certificate) GetFp() string {
	if x != nil {
		return x.Fp
	}
	return ""
}

func (x *Certificate) GetNotBeforeSec() int64 {
	if x != nil {
		return x.NotBeforeSec
	}
	return 0
}

func (x *Certificate) GetNotAfterSec() int64 {
	if x != nil {
		return x.NotAfterSec
	}
	return 0
}

func (x *Certificate) GetTtlSec() int64 {
	if x != nil {
		return x.TtlSec
	}
	return 0
}

func (x *Certificate) GetHasOcspStapling() bool {
	if x != nil {
		return x.HasOcspStapling
	}
	return false
}

type OCSPStapling struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Raw           []byte `protobuf:"bytes,1,opt,name=raw,proto3" json:"raw,omitempty"`
	NextUpdateSec int64  `protobuf:"varint,2,opt,name=next_update_sec,json=nextUpdateSec,proto3" json:"next_update_sec,omitempty"`
	TtlSec        int64  `protobuf:"varint,3,opt,name=ttl_sec,json=ttlSec,proto3" json:"ttl_sec,omitempty"`
}

func (x *OCSPStapling) Reset() {
	*x = OCSPStapling{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OCSPStapling) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OCSPStapling) ProtoMessage() {}

func (x *OCSPStapling) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OCSPStapling.ProtoReflect.Descriptor instead.
func (*OCSPStapling) Descriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{1}
}

func (x *OCSPStapling) GetRaw() []byte {
	if x != nil {
		return x.Raw
	}
	return nil
}

func (x *OCSPStapling) GetNextUpdateSec() int64 {
	if x != nil {
		return x.NextUpdateSec
	}
	return 0
}

func (x *OCSPStapling) GetTtlSec() int64 {
	if x != nil {
		return x.TtlSec
	}
	return 0
}

type GetCertificateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Domain           string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	Name             string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	IsAlpn           bool   `protobuf:"varint,11,opt,name=is_alpn,json=isAlpn,proto3" json:"is_alpn,omitempty"`
	WantOcspStapling bool   `protobuf:"varint,12,opt,name=want_ocsp_stapling,json=wantOcspStapling,proto3" json:"want_ocsp_stapling,omitempty"`
}

func (x *GetCertificateRequest) Reset() {
	*x = GetCertificateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertificateRequest) ProtoMessage() {}

func (x *GetCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertificateRequest.ProtoReflect.Descriptor instead.
func (*GetCertificateRequest) Descriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{2}
}

func (x *GetCertificateRequest) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *GetCertificateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GetCertificateRequest) GetIsAlpn() bool {
	if x != nil {
		return x.IsAlpn
	}
	return false
}

func (x *GetCertificateRequest) GetWantOcspStapling() bool {
	if x != nil {
		return x.WantOcspStapling
	}
	return false
}

type GetCertificateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Cert         *Certificate  `protobuf:"bytes,1,opt,name=cert,proto3" json:"cert,omitempty"`
	OcspStapling *OCSPStapling `protobuf:"bytes,3,opt,name=ocsp_stapling,json=ocspStapling,proto3" json:"ocsp_stapling,omitempty"`
}

func (x *GetCertificateResponse) Reset() {
	*x = GetCertificateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertificateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertificateResponse) ProtoMessage() {}

func (x *GetCertificateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertificateResponse.ProtoReflect.Descriptor instead.
func (*GetCertificateResponse) Descriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{3}
}

func (x *GetCertificateResponse) GetCert() *Certificate {
	if x != nil {
		return x.Cert
	}
	return nil
}

func (x *GetCertificateResponse) GetOcspStapling() *OCSPStapling {
	if x != nil {
		return x.OcspStapling
	}
	return nil
}

type GetOCSPStaplingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Domain      string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	Fingerprint string `protobuf:"bytes,2,opt,name=fingerprint,proto3" json:"fingerprint,omitempty"`
}

func (x *GetOCSPStaplingRequest) Reset() {
	*x = GetOCSPStaplingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetOCSPStaplingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOCSPStaplingRequest) ProtoMessage() {}

func (x *GetOCSPStaplingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOCSPStaplingRequest.ProtoReflect.Descriptor instead.
func (*GetOCSPStaplingRequest) Descriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{4}
}

func (x *GetOCSPStaplingRequest) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *GetOCSPStaplingRequest) GetFingerprint() string {
	if x != nil {
		return x.Fingerprint
	}
	return ""
}

type GetOCSPStaplingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OcspStapling *OCSPStapling `protobuf:"bytes,1,opt,name=ocsp_stapling,json=ocspStapling,proto3" json:"ocsp_stapling,omitempty"`
}

func (x *GetOCSPStaplingResponse) Reset() {
	*x = GetOCSPStaplingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetOCSPStaplingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOCSPStaplingResponse) ProtoMessage() {}

func (x *GetOCSPStaplingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOCSPStaplingResponse.ProtoReflect.Descriptor instead.
func (*GetOCSPStaplingResponse) Descriptor() ([]byte, []int) {
	return file_api_proto_rawDescGZIP(), []int{5}
}

func (x *GetOCSPStaplingResponse) GetOcspStapling() *OCSPStapling {
	if x != nil {
		return x.OcspStapling
	}
	return nil
}

var File_api_proto protoreflect.FileDescriptor

var file_api_proto_rawDesc = []byte{
	0x0a, 0x09, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x73, 0x73, 0x6c,
	0x63, 0x65, 0x72, 0x74, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x22, 0xd5, 0x02, 0x0a, 0x0b, 0x43,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x17,
	0x0a, 0x07, 0x70, 0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x70, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x72, 0x69, 0x76, 0x5f,
	0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x72, 0x69, 0x76, 0x4b,
	0x65, 0x79, 0x12, 0x0e, 0x0a, 0x02, 0x66, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x66, 0x70, 0x12, 0x24, 0x0a, 0x0e, 0x6e, 0x6f, 0x74, 0x5f, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65,
	0x5f, 0x73, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0c, 0x6e, 0x6f, 0x74, 0x42,
	0x65, 0x66, 0x6f, 0x72, 0x65, 0x53, 0x65, 0x63, 0x12, 0x22, 0x0a, 0x0d, 0x6e, 0x6f, 0x74, 0x5f,
	0x61, 0x66, 0x74, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x63, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x0b, 0x6e, 0x6f, 0x74, 0x41, 0x66, 0x74, 0x65, 0x72, 0x53, 0x65, 0x63, 0x12, 0x17, 0x0a, 0x07,
	0x74, 0x74, 0x6c, 0x5f, 0x73, 0x65, 0x63, 0x18, 0x07, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x74,
	0x74, 0x6c, 0x53, 0x65, 0x63, 0x12, 0x2a, 0x0a, 0x11, 0x68, 0x61, 0x73, 0x5f, 0x6f, 0x63, 0x73,
	0x70, 0x5f, 0x73, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0f, 0x68, 0x61, 0x73, 0x4f, 0x63, 0x73, 0x70, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e,
	0x67, 0x22, 0x5f, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b,
	0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x41, 0x4c, 0x50, 0x4e, 0x10, 0x01,
	0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x45, 0x4c, 0x46, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x45, 0x44, 0x10,
	0x02, 0x12, 0x0b, 0x0a, 0x07, 0x4d, 0x41, 0x4e, 0x41, 0x47, 0x45, 0x44, 0x10, 0x03, 0x12, 0x12,
	0x0a, 0x0e, 0x41, 0x43, 0x4d, 0x45, 0x5f, 0x4f, 0x4e, 0x5f, 0x44, 0x45, 0x4d, 0x41, 0x4e, 0x44,
	0x10, 0x0b, 0x12, 0x0e, 0x0a, 0x0a, 0x41, 0x43, 0x4d, 0x45, 0x5f, 0x4e, 0x41, 0x4d, 0x45, 0x44,
	0x10, 0x0c, 0x22, 0x61, 0x0a, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69,
	0x6e, 0x67, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x61, 0x77, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x03, 0x72, 0x61, 0x77, 0x12, 0x26, 0x0a, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x75, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x63, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x6e,
	0x65, 0x78, 0x74, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x65, 0x63, 0x12, 0x17, 0x0a, 0x07,
	0x74, 0x74, 0x6c, 0x5f, 0x73, 0x65, 0x63, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x74,
	0x74, 0x6c, 0x53, 0x65, 0x63, 0x22, 0x8a, 0x01, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x69,
	0x73, 0x5f, 0x61, 0x6c, 0x70, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x69, 0x73,
	0x41, 0x6c, 0x70, 0x6e, 0x12, 0x2c, 0x0a, 0x12, 0x77, 0x61, 0x6e, 0x74, 0x5f, 0x6f, 0x63, 0x73,
	0x70, 0x5f, 0x73, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x10, 0x77, 0x61, 0x6e, 0x74, 0x4f, 0x63, 0x73, 0x70, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69,
	0x6e, 0x67, 0x22, 0x8a, 0x01, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2e, 0x0a,
	0x04, 0x63, 0x65, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x73, 0x73,
	0x6c, 0x63, 0x65, 0x72, 0x74, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x04, 0x63, 0x65, 0x72, 0x74, 0x12, 0x40, 0x0a,
	0x0d, 0x6f, 0x63, 0x73, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x73, 0x73, 0x6c, 0x63, 0x65, 0x72, 0x74, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x2e, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e,
	0x67, 0x52, 0x0c, 0x6f, 0x63, 0x73, 0x70, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x22,
	0x52, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69,
	0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69,
	0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72,
	0x69, 0x6e, 0x74, 0x22, 0x5b, 0x0a, 0x17, 0x47, 0x65, 0x74, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74,
	0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x40,
	0x0a, 0x0d, 0x6f, 0x63, 0x73, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x73, 0x73, 0x6c, 0x63, 0x65, 0x72, 0x74, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69,
	0x6e, 0x67, 0x52, 0x0c, 0x6f, 0x63, 0x73, 0x70, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67,
	0x32, 0xcd, 0x01, 0x0a, 0x0a, 0x43, 0x65, 0x72, 0x74, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12,
	0x5d, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x12, 0x24, 0x2e, 0x73, 0x73, 0x6c, 0x63, 0x65, 0x72, 0x74, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x73, 0x73, 0x6c, 0x63, 0x65, 0x72,
	0x74, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x60,
	0x0a, 0x0f, 0x47, 0x65, 0x74, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e,
	0x67, 0x12, 0x25, 0x2e, 0x73, 0x73, 0x6c, 0x63, 0x65, 0x72, 0x74, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x2e, 0x47, 0x65, 0x74, 0x4f, 0x43, 0x53, 0x50, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e,
	0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x73, 0x73, 0x6c, 0x63, 0x65,
	0x72, 0x74, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x4f, 0x43, 0x53, 0x50,
	0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x25, 0x5a, 0x23, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6a,
	0x78, 0x73, 0x6b, 0x69, 0x73, 0x73, 0x2f, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x73, 0x73, 0x6c,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_proto_rawDescOnce sync.Once
	file_api_proto_rawDescData = file_api_proto_rawDesc
)

func file_api_proto_rawDescGZIP() []byte {
	file_api_proto_rawDescOnce.Do(func() {
		file_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_proto_rawDescData)
	})
	return file_api_proto_rawDescData
}

var file_api_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_api_proto_goTypes = []interface{}{
	(Certificate_Type)(0),           // 0: sslcertserver.Certificate.Type
	(*Certificate)(nil),             // 1: sslcertserver.Certificate
	(*OCSPStapling)(nil),            // 2: sslcertserver.OCSPStapling
	(*GetCertificateRequest)(nil),   // 3: sslcertserver.GetCertificateRequest
	(*GetCertificateResponse)(nil),  // 4: sslcertserver.GetCertificateResponse
	(*GetOCSPStaplingRequest)(nil),  // 5: sslcertserver.GetOCSPStaplingRequest
	(*GetOCSPStaplingResponse)(nil), // 6: sslcertserver.GetOCSPStaplingResponse
}
var file_api_proto_depIdxs = []int32{
	1, // 0: sslcertserver.GetCertificateResponse.cert:type_name -> sslcertserver.Certificate
	2, // 1: sslcertserver.GetCertificateResponse.ocsp_stapling:type_name -> sslcertserver.OCSPStapling
	2, // 2: sslcertserver.GetOCSPStaplingResponse.ocsp_stapling:type_name -> sslcertserver.OCSPStapling
	3, // 3: sslcertserver.CertServer.GetCertificate:input_type -> sslcertserver.GetCertificateRequest
	5, // 4: sslcertserver.CertServer.GetOCSPStapling:input_type -> sslcertserver.GetOCSPStaplingRequest
	4, // 5: sslcertserver.CertServer.GetCertificate:output_type -> sslcertserver.GetCertificateResponse
	6, // 6: sslcertserver.CertServer.GetOCSPStapling:output_type -> sslcertserver.GetOCSPStaplingResponse
	5, // [5:7] is the sub-list for method output_type
	3, // [3:5] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_api_proto_init() }
func file_api_proto_init() {
	if File_api_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Certificate); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OCSPStapling); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertificateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertificateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetOCSPStaplingRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetOCSPStaplingResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_proto_goTypes,
		DependencyIndexes: file_api_proto_depIdxs,
		EnumInfos:         file_api_proto_enumTypes,
		MessageInfos:      file_api_proto_msgTypes,
	}.Build()
	File_api_proto = out.File
	file_api_proto_rawDesc = nil
	file_api_proto_goTypes = nil
	file_api_proto_depIdxs = nil
}
