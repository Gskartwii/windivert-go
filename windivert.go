package windivert

/*
#cgo CFLAGS: -Iinclude
#cgo LDFLAGS: -L. -lwindivert
#include <stdlib.h>
#include <windivert.h>

// Hacky TODO
typedef struct {
	INT64 Timestamp;
	UINT32 IfIdx;
	UINT32 SubIfIdx;
	union {
		struct {
			UINT8 Direction:1;
			UINT8 Loopback:1;
			UINT8 Impostor:1;
			UINT8 PseudoIPChecksum:1;
			UINT8 PseudoTCPChecksum:1;
			UINT8 PseudoUDPChecksum:1;
			UINT8 Reserved:2;
		};
		UINT8 Flags;
	} FlagUnion;
} WINDIVERT_ADDRESS_FLAGS;

char* GetErrorMessage(DWORD errCode) {
	LPSTR message;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_IGNORE_INSERTS,0,errCode,0,(LPSTR)&message,0,NULL);
	return (char*)message;
}
char* GetLastErrorString() {
	DWORD errCode = GetLastError();
	return GetErrorMessage(errCode);
}
*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Layer uint8
type Param uint8
type AddrFlags uint8
type HandleFlags uint64

const (
	PseudoUDPChecksum AddrFlags = 1 << 2
	PseudoTCPChecksum           = 1 << 3
	PseudoIPChecksum            = 1 << 4
	Impostor                    = 1 << 5
	Loopback                    = 1 << 6
	IsOutbound                  = 1 << 7
)

const (
	LayerNetwork        Layer = 0
	LayerNetworkForward       = 1
)

const (
	ParamQueueLen  Param = 0
	ParamQueueTime       = 1
	ParamQueueSize       = 2
)

const (
	FlagSniff HandleFlags = C.WINDIVERT_FLAG_SNIFF
	FlagDrop              = C.WINDIVERT_FLAG_DROP
	FlagDebug             = C.WINDIVERT_FLAG_DEBUG
)

type Address struct {
	Timestamp         int64
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	Flags             AddrFlags
}

func GetLastError() error {
	errString := C.GetLastErrorString()
	err := errors.New(C.GoString(errString))
	C.LocalFree(C.HLOCAL(errString))
	return err
}
func GetErrorMessage(errCode C.DWORD) error {
	errString := C.GetErrorMessage(errCode)
	err := errors.New(C.GoString(errString))
	C.LocalFree(C.HLOCAL(errString))
	return err
}

var invalidHandle C.HANDLE

const cFalse = C.FALSE

func init() {
	invalidHandle = C.HANDLE(C.INVALID_HANDLE_VALUE)
}

// Convert C struct to a Go-friendly form
func addressFromCGo(addr *C.WINDIVERT_ADDRESS_FLAGS) *Address {
	newaddr := new(Address)
	newaddr.Timestamp = int64(addr.Timestamp)
	newaddr.InterfaceIndex = uint32(addr.IfIdx)
	newaddr.SubInterfaceIndex = uint32(addr.SubIfIdx)
	newaddr.Flags = AddrFlags(*(*uint8)(unsafe.Pointer(&addr.FlagUnion)))

	return newaddr
}

// Convert Go-friendly form to a C struct
func cgoFromAddress(addr *Address) *C.WINDIVERT_ADDRESS_FLAGS {
	newaddr := new(C.WINDIVERT_ADDRESS_FLAGS)
	newaddr.Timestamp = C.INT64(addr.Timestamp)
	newaddr.IfIdx = C.UINT32(addr.InterfaceIndex)
	newaddr.SubIfIdx = C.UINT32(addr.SubInterfaceIndex)
	*(*uint8)(unsafe.Pointer(&newaddr.FlagUnion)) = uint8(addr.Flags)

	return newaddr
}

type Handle struct {
	handle   C.HANDLE
	filterCs *C.char
}

func Open(filter string, layer Layer, priority int16, flags HandleFlags) (*Handle, error) {
	handle := new(Handle)
	println("opening with filter", filter)
	handle.filterCs = C.CString(filter)
	handle.handle = C.WinDivertOpen(handle.filterCs, C.WINDIVERT_LAYER(layer), C.short(priority), C.ulonglong(flags))
	if handle.handle == invalidHandle { // INVALID_HANDLE_VALUE
		lastError := C.GetLastError()
		if lastError == C.ERROR_INVALID_PARAMETER {
			var errorString *C.char // Doesn't need to be freed, points at const char*
			var errorPos C.UINT

			isFilterValid := C.WinDivertHelperCheckFilter(handle.filterCs, C.WINDIVERT_LAYER(layer), &errorString, &errorPos)
			if isFilterValid == cFalse {
				return handle, fmt.Errorf("filter error at %d: %s", uint(errorPos), C.GoString(errorString))
			}
		}
		return handle, GetErrorMessage(lastError)
	}

	return handle, nil
}

func (handle *Handle) Recv(buf []byte) (*Address, uint32, error) {
	var address C.WINDIVERT_ADDRESS
	var recvLen C.uint
	success := C.WinDivertRecv(handle.handle, C.PVOID(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(&address)), &recvLen)
	trueAddress := addressFromCGo((*C.WINDIVERT_ADDRESS_FLAGS)(unsafe.Pointer(&address)))
	if success == cFalse { // FALSE
		return trueAddress, uint32(recvLen), GetLastError()
	}
	return trueAddress, uint32(recvLen), nil
}

func (handle *Handle) Send(packet []byte, address *Address) (uint32, error) {
	trueAddress := (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(cgoFromAddress(address)))
	var sendLen C.uint
	success := C.WinDivertSend(handle.handle, C.PVOID(unsafe.Pointer(&packet[0])), C.uint(len(packet)), trueAddress, &sendLen)
	if success == cFalse { // FALSE
		return uint32(sendLen), GetLastError()
	}

	return uint32(sendLen), nil
}

func (handle *Handle) Close() error {
	defer C.free(unsafe.Pointer(handle.filterCs))
	success := C.WinDivertClose(handle.handle)
	if success == cFalse {
		return GetLastError()
	}
	return nil
}

func (handle *Handle) SetParam(param Param, value uint64) error {
	success := C.WinDivertSetParam(handle.handle, C.WINDIVERT_PARAM(param), C.UINT64(value))
	if success == cFalse {
		return GetLastError()
	}
	return nil
}

func (handle *Handle) GetParam(param Param) (uint64, error) {
	var value C.UINT64
	success := C.WinDivertGetParam(handle.handle, C.WINDIVERT_PARAM(param), &value)
	if success == cFalse {
		return uint64(value), GetLastError()
	}
	return uint64(value), nil
}

type ChecksumFlags uint64

const (
	NoIpChecksum   ChecksumFlags = C.WINDIVERT_HELPER_NO_IP_CHECKSUM
	NoIcmpChecksum ChecksumFlags = C.WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM
	NoTcpChecksum  ChecksumFlags = C.WINDIVERT_HELPER_NO_TCP_CHECKSUM
	NoUdpChecksum  ChecksumFlags = C.WINDIVERT_HELPER_NO_UDP_CHECKSUM
)

func CalculateChecksums(packet []byte, address *Address, flags ChecksumFlags) uint {
	numChecksums := C.WinDivertHelperCalcChecksums(C.PVOID(unsafe.Pointer(&packet[0])), C.UINT(len(packet)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(cgoFromAddress(address))), C.UINT64(flags))

	return uint(numChecksums)
}

func ExtractUDP(packet []byte) (*net.UDPAddr, *net.UDPAddr, []byte, error) {
	goPkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	ipv4Layer := goPkt.Layer(layers.LayerTypeIPv4)
	udpLayer := goPkt.Layer(layers.LayerTypeUDP)
	if ipv4Layer == nil || udpLayer == nil {
		return nil, nil, packet, errors.New("not a udp packet!")
	}
	ipv4Layer2 := ipv4Layer.(*layers.IPv4)
	udpLayer2 := udpLayer.(*layers.UDP)

	srcAddr := &net.UDPAddr{IP: ipv4Layer2.SrcIP, Port: int(udpLayer2.SrcPort)}
	dstAddr := &net.UDPAddr{IP: ipv4Layer2.DstIP, Port: int(udpLayer2.DstPort)}

	return srcAddr, dstAddr, udpLayer2.Payload, nil
}

func (handle *Handle) SendUDP(packet []byte, src *net.UDPAddr, dst *net.UDPAddr, isOutbound bool, ifIdx uint32, subIfIdx uint32) error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	ipv4Layer := &layers.IPv4{
		Version:    4,
		IHL:        5, // Normal IHL value
		TOS:        0,
		Id:         0,
		Flags:      1 << 1, // Don't fragment (default)
		FragOffset: 0,
		TTL:        255,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      src.IP,
		DstIP:      dst.IP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(src.Port),
		DstPort: layers.UDPPort(dst.Port),
	}
	udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	err := gopacket.SerializeLayers(buf, opts,
		ipv4Layer,
		udpLayer,
		gopacket.Payload(packet),
	)
	if err != nil {
		return err
	}

	address := &Address{InterfaceIndex: ifIdx, SubInterfaceIndex: subIfIdx}
	if isOutbound {
		address.Flags = IsOutbound
	}

	length, err := handle.Send(buf.Bytes(), address)
	if err != nil {
		return err
	}
	if length < uint32(len(buf.Bytes())) {
		return errors.New("didn't send all bytes?")
	}
	return nil
}
