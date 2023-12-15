// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.15.3
// source: proto/daemon/v1/hummingbird.proto

package daemon

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

type StoreFlyoversRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Flyovers []*Flyover `protobuf:"bytes,1,rep,name=flyovers,proto3" json:"flyovers,omitempty"`
}

func (x *StoreFlyoversRequest) Reset() {
	*x = StoreFlyoversRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreFlyoversRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreFlyoversRequest) ProtoMessage() {}

func (x *StoreFlyoversRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreFlyoversRequest.ProtoReflect.Descriptor instead.
func (*StoreFlyoversRequest) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{0}
}

func (x *StoreFlyoversRequest) GetFlyovers() []*Flyover {
	if x != nil {
		return x.Flyovers
	}
	return nil
}

type StoreFlyoversResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StoreFlyoversResponse) Reset() {
	*x = StoreFlyoversResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreFlyoversResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreFlyoversResponse) ProtoMessage() {}

func (x *StoreFlyoversResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreFlyoversResponse.ProtoReflect.Descriptor instead.
func (*StoreFlyoversResponse) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{1}
}

type ListFlyoversRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ListFlyoversRequest) Reset() {
	*x = ListFlyoversRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListFlyoversRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListFlyoversRequest) ProtoMessage() {}

func (x *ListFlyoversRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListFlyoversRequest.ProtoReflect.Descriptor instead.
func (*ListFlyoversRequest) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{2}
}

type ListFlyoversResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Flyovers []*Flyover `protobuf:"bytes,1,rep,name=flyovers,proto3" json:"flyovers,omitempty"`
}

func (x *ListFlyoversResponse) Reset() {
	*x = ListFlyoversResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListFlyoversResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListFlyoversResponse) ProtoMessage() {}

func (x *ListFlyoversResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListFlyoversResponse.ProtoReflect.Descriptor instead.
func (*ListFlyoversResponse) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{3}
}

func (x *ListFlyoversResponse) GetFlyovers() []*Flyover {
	if x != nil {
		return x.Flyovers
	}
	return nil
}

type GetReservationsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SourceIsdAs      uint64 `protobuf:"varint,1,opt,name=source_isd_as,json=sourceIsdAs,proto3" json:"source_isd_as,omitempty"`
	DestinationIsdAs uint64 `protobuf:"varint,2,opt,name=destination_isd_as,json=destinationIsdAs,proto3" json:"destination_isd_as,omitempty"`
	Refresh          bool   `protobuf:"varint,3,opt,name=refresh,proto3" json:"refresh,omitempty"`
	MinBandwidth     uint64 `protobuf:"varint,4,opt,name=min_bandwidth,json=minBandwidth,proto3" json:"min_bandwidth,omitempty"`
}

func (x *GetReservationsRequest) Reset() {
	*x = GetReservationsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetReservationsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetReservationsRequest) ProtoMessage() {}

func (x *GetReservationsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetReservationsRequest.ProtoReflect.Descriptor instead.
func (*GetReservationsRequest) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{4}
}

func (x *GetReservationsRequest) GetSourceIsdAs() uint64 {
	if x != nil {
		return x.SourceIsdAs
	}
	return 0
}

func (x *GetReservationsRequest) GetDestinationIsdAs() uint64 {
	if x != nil {
		return x.DestinationIsdAs
	}
	return 0
}

func (x *GetReservationsRequest) GetRefresh() bool {
	if x != nil {
		return x.Refresh
	}
	return false
}

func (x *GetReservationsRequest) GetMinBandwidth() uint64 {
	if x != nil {
		return x.MinBandwidth
	}
	return 0
}

type GetReservationsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reservations []*Reservation `protobuf:"bytes,1,rep,name=reservations,proto3" json:"reservations,omitempty"`
}

func (x *GetReservationsResponse) Reset() {
	*x = GetReservationsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetReservationsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetReservationsResponse) ProtoMessage() {}

func (x *GetReservationsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetReservationsResponse.ProtoReflect.Descriptor instead.
func (*GetReservationsResponse) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{5}
}

func (x *GetReservationsResponse) GetReservations() []*Reservation {
	if x != nil {
		return x.Reservations
	}
	return nil
}

type Flyover struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ia        uint64 `protobuf:"varint,1,opt,name=ia,proto3" json:"ia,omitempty"`
	Ingress   uint32 `protobuf:"varint,2,opt,name=ingress,proto3" json:"ingress,omitempty"`
	Egress    uint32 `protobuf:"varint,3,opt,name=egress,proto3" json:"egress,omitempty"`
	Bw        uint32 `protobuf:"varint,4,opt,name=bw,proto3" json:"bw,omitempty"`
	StartTime uint32 `protobuf:"varint,5,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	Duration  uint32 `protobuf:"varint,6,opt,name=duration,proto3" json:"duration,omitempty"`
	ResId     uint32 `protobuf:"varint,7,opt,name=res_id,json=resId,proto3" json:"res_id,omitempty"`
	Ak        []byte `protobuf:"bytes,8,opt,name=ak,proto3" json:"ak,omitempty"`
}

func (x *Flyover) Reset() {
	*x = Flyover{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Flyover) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Flyover) ProtoMessage() {}

func (x *Flyover) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Flyover.ProtoReflect.Descriptor instead.
func (*Flyover) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{6}
}

func (x *Flyover) GetIa() uint64 {
	if x != nil {
		return x.Ia
	}
	return 0
}

func (x *Flyover) GetIngress() uint32 {
	if x != nil {
		return x.Ingress
	}
	return 0
}

func (x *Flyover) GetEgress() uint32 {
	if x != nil {
		return x.Egress
	}
	return 0
}

func (x *Flyover) GetBw() uint32 {
	if x != nil {
		return x.Bw
	}
	return 0
}

func (x *Flyover) GetStartTime() uint32 {
	if x != nil {
		return x.StartTime
	}
	return 0
}

func (x *Flyover) GetDuration() uint32 {
	if x != nil {
		return x.Duration
	}
	return 0
}

func (x *Flyover) GetResId() uint32 {
	if x != nil {
		return x.ResId
	}
	return 0
}

func (x *Flyover) GetAk() []byte {
	if x != nil {
		return x.Ak
	}
	return nil
}

type Reservation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Raw      []byte     `protobuf:"bytes,1,opt,name=raw,proto3" json:"raw,omitempty"`
	Flyovers []*Flyover `protobuf:"bytes,2,rep,name=flyovers,proto3" json:"flyovers,omitempty"`
	Ratio    float64    `protobuf:"fixed64,3,opt,name=ratio,proto3" json:"ratio,omitempty"`
}

func (x *Reservation) Reset() {
	*x = Reservation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Reservation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Reservation) ProtoMessage() {}

func (x *Reservation) ProtoReflect() protoreflect.Message {
	mi := &file_proto_daemon_v1_hummingbird_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Reservation.ProtoReflect.Descriptor instead.
func (*Reservation) Descriptor() ([]byte, []int) {
	return file_proto_daemon_v1_hummingbird_proto_rawDescGZIP(), []int{7}
}

func (x *Reservation) GetRaw() []byte {
	if x != nil {
		return x.Raw
	}
	return nil
}

func (x *Reservation) GetFlyovers() []*Flyover {
	if x != nil {
		return x.Flyovers
	}
	return nil
}

func (x *Reservation) GetRatio() float64 {
	if x != nil {
		return x.Ratio
	}
	return 0
}

var File_proto_daemon_v1_hummingbird_proto protoreflect.FileDescriptor

var file_proto_daemon_v1_hummingbird_proto_rawDesc = []byte{
	0x0a, 0x21, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x2f, 0x76,
	0x31, 0x2f, 0x68, 0x75, 0x6d, 0x6d, 0x69, 0x6e, 0x67, 0x62, 0x69, 0x72, 0x64, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x61, 0x65, 0x6d, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x22, 0x4c, 0x0a, 0x14, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x46, 0x6c, 0x79,
	0x6f, 0x76, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x08,
	0x66, 0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31,
	0x2e, 0x46, 0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x52, 0x08, 0x66, 0x6c, 0x79, 0x6f, 0x76, 0x65,
	0x72, 0x73, 0x22, 0x17, 0x0a, 0x15, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x46, 0x6c, 0x79, 0x6f, 0x76,
	0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x15, 0x0a, 0x13, 0x4c,
	0x69, 0x73, 0x74, 0x46, 0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x4c, 0x0a, 0x14, 0x4c, 0x69, 0x73, 0x74, 0x46, 0x6c, 0x79, 0x6f, 0x76, 0x65,
	0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x34, 0x0a, 0x08, 0x66, 0x6c,
	0x79, 0x6f, 0x76, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x46,
	0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x52, 0x08, 0x66, 0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x73,
	0x22, 0xa9, 0x01, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x52, 0x65, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x22, 0x0a, 0x0d, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x73, 0x64, 0x5f, 0x61, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x73, 0x64, 0x41, 0x73, 0x12,
	0x2c, 0x0a, 0x12, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69,
	0x73, 0x64, 0x5f, 0x61, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x10, 0x64, 0x65, 0x73,
	0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x73, 0x64, 0x41, 0x73, 0x12, 0x18, 0x0a,
	0x07, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07,
	0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x12, 0x23, 0x0a, 0x0d, 0x6d, 0x69, 0x6e, 0x5f, 0x62,
	0x61, 0x6e, 0x64, 0x77, 0x69, 0x64, 0x74, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c,
	0x6d, 0x69, 0x6e, 0x42, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x5b, 0x0a, 0x17,
	0x47, 0x65, 0x74, 0x52, 0x65, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x40, 0x0a, 0x0c, 0x72, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e,
	0x52, 0x65, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0c, 0x72, 0x65, 0x73,
	0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0xbd, 0x01, 0x0a, 0x07, 0x46, 0x6c,
	0x79, 0x6f, 0x76, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x02, 0x69, 0x61, 0x12, 0x18, 0x0a, 0x07, 0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12,
	0x16, 0x0a, 0x06, 0x65, 0x67, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x06, 0x65, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x62, 0x77, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x02, 0x62, 0x77, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x73, 0x74, 0x61,
	0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x15, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x05, 0x72, 0x65, 0x73, 0x49, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x61, 0x6b, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x61, 0x6b, 0x22, 0x6b, 0x0a, 0x0b, 0x52, 0x65, 0x73,
	0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x61, 0x77, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x72, 0x61, 0x77, 0x12, 0x34, 0x0a, 0x08, 0x66, 0x6c,
	0x79, 0x6f, 0x76, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x46,
	0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x52, 0x08, 0x66, 0x6c, 0x79, 0x6f, 0x76, 0x65, 0x72, 0x73,
	0x12, 0x14, 0x0a, 0x05, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x01, 0x52,
	0x05, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x63, 0x69, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x73, 0x63, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_daemon_v1_hummingbird_proto_rawDescOnce sync.Once
	file_proto_daemon_v1_hummingbird_proto_rawDescData = file_proto_daemon_v1_hummingbird_proto_rawDesc
)

func file_proto_daemon_v1_hummingbird_proto_rawDescGZIP() []byte {
	file_proto_daemon_v1_hummingbird_proto_rawDescOnce.Do(func() {
		file_proto_daemon_v1_hummingbird_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_daemon_v1_hummingbird_proto_rawDescData)
	})
	return file_proto_daemon_v1_hummingbird_proto_rawDescData
}

var file_proto_daemon_v1_hummingbird_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_proto_daemon_v1_hummingbird_proto_goTypes = []interface{}{
	(*StoreFlyoversRequest)(nil),    // 0: proto.daemon.v1.StoreFlyoversRequest
	(*StoreFlyoversResponse)(nil),   // 1: proto.daemon.v1.StoreFlyoversResponse
	(*ListFlyoversRequest)(nil),     // 2: proto.daemon.v1.ListFlyoversRequest
	(*ListFlyoversResponse)(nil),    // 3: proto.daemon.v1.ListFlyoversResponse
	(*GetReservationsRequest)(nil),  // 4: proto.daemon.v1.GetReservationsRequest
	(*GetReservationsResponse)(nil), // 5: proto.daemon.v1.GetReservationsResponse
	(*Flyover)(nil),                 // 6: proto.daemon.v1.Flyover
	(*Reservation)(nil),             // 7: proto.daemon.v1.Reservation
}
var file_proto_daemon_v1_hummingbird_proto_depIdxs = []int32{
	6, // 0: proto.daemon.v1.StoreFlyoversRequest.flyovers:type_name -> proto.daemon.v1.Flyover
	6, // 1: proto.daemon.v1.ListFlyoversResponse.flyovers:type_name -> proto.daemon.v1.Flyover
	7, // 2: proto.daemon.v1.GetReservationsResponse.reservations:type_name -> proto.daemon.v1.Reservation
	6, // 3: proto.daemon.v1.Reservation.flyovers:type_name -> proto.daemon.v1.Flyover
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_proto_daemon_v1_hummingbird_proto_init() }
func file_proto_daemon_v1_hummingbird_proto_init() {
	if File_proto_daemon_v1_hummingbird_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_daemon_v1_hummingbird_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreFlyoversRequest); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreFlyoversResponse); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListFlyoversRequest); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListFlyoversResponse); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetReservationsRequest); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetReservationsResponse); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Flyover); i {
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
		file_proto_daemon_v1_hummingbird_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Reservation); i {
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
			RawDescriptor: file_proto_daemon_v1_hummingbird_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_daemon_v1_hummingbird_proto_goTypes,
		DependencyIndexes: file_proto_daemon_v1_hummingbird_proto_depIdxs,
		MessageInfos:      file_proto_daemon_v1_hummingbird_proto_msgTypes,
	}.Build()
	File_proto_daemon_v1_hummingbird_proto = out.File
	file_proto_daemon_v1_hummingbird_proto_rawDesc = nil
	file_proto_daemon_v1_hummingbird_proto_goTypes = nil
	file_proto_daemon_v1_hummingbird_proto_depIdxs = nil
}
