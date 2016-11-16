package gss

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -lgssapi_krb5

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

static void set_elem_from_gss_oid(gss_OID oid, void* value)
{
	oid->elements = value;
}

static void* get_elem_from_gss_oid(gss_OID oid)
{
	return oid->elements;
}

static void* get_elem_from_gss_oid_desc(gss_OID_desc oid)
{
	return oid.elements;
}

static void free_oid(gss_OID oid)
{
	if (oid != NULL) {
		free(oid->elements);
		free(oid);
	}
}

static void *
copyOid(unsigned char *bytes, int len)
{
	void *ret;

	if (len < 0) {
		return NULL;
	}
	ret = malloc(len);
	if (ret != NULL) {
		memcpy(ret, bytes, len);
	}
	return ret;
}
*/
import "C"
import "unsafe"
import "encoding/asn1"

type CredHandle C.gss_cred_id_t
type ContextHandle C.gss_ctx_id_t
type InternalName C.gss_name_t

type ChannelBindings struct {
	// These four fields are deprecated.
	//initiatorAddressType uint32
	//acceptorAddressType          uint32
	//initiatorAddress []byte
	//acceptorAddress []byte
	ApplicationData []byte
}

type Flags struct {
	Deleg, DelegPolicy, Mutual, Replay, Sequence, Anon, Conf, Integ, Trans, ProtReady bool
}

func makeTagAndLength(tag, length int) (l []byte) {
	var count, bits int

	if length <= 127 {
		l = make([]byte, 2)
		l[0] = byte(tag)
		l[1] = byte(length)
		return
	}
	count = 0
	bits = length
	for bits != 0 {
		count++
		bits = bits >> 8
	}
	if count > 126 {
		return nil
	}
	l = make([]byte, 2+count)
	count = 0
	bits = length
	l[0] = byte(tag)
	for bits != 0 {
		l[len(l)-1-count] = byte(bits & 0xff)
		count++
		bits = bits >> 8
	}
	l[1] = byte(count | 0x80)
	return
}

func coidToOid(coid C.gss_OID_desc) (oid asn1.ObjectIdentifier) {
	length := C.int(coid.length)
	//b := C.GoBytes(coid.elements, length)
	b := C.GoBytes(C.get_elem_from_gss_oid_desc(coid), length)

	b = append(makeTagAndLength(6, len(b)), b...)
	asn1.Unmarshal(b, &oid)
	return
}

func bytesToBuffer(data []byte) (cdesc C.gss_buffer_desc) {
	value := unsafe.Pointer(&data[0])
	length := C.size_t(len(data))

	cdesc.value = value
	cdesc.length = length
	return
}

func oidToCOid(oid asn1.ObjectIdentifier) (coid C.gss_OID) {
	if oid == nil {
		return
	}

	b, _ := asn1.Marshal(oid)
	if b == nil {
		return
	}
	_, _, _, _, v := splitTagAndLength(b)
	if v == nil {
		return
	}
	length := len(v)
	if length == 0 {
		return
	}
	coid = C.gss_OID(C.calloc(1, C.size_t(unsafe.Sizeof(*coid))))
	coid.length = C.OM_uint32(length)
	//coid.elements = C.copyOid((*C.uchar)(&v[0]), C.int(length))
	C.set_elem_from_gss_oid(coid, C.copyOid((*C.uchar)(&v[0]), C.int(length)))
	if C.get_elem_from_gss_oid(coid) == nil {
		C.free_oid(coid)
		coid = nil
	}
	return
}

func splitTagAndLength(tlv []byte) (class int, constructed bool, tag, length int, value []byte) {
	tbytes := 1
	lbytes := 1

	class = int((tlv[0] & 0xc0) >> 6)
	constructed = (tlv[0] & 0x20) != 0
	tag = int(tlv[0] & 0x1f)
	if tag == 0x1f {
		tag = 0
		for tlv[tbytes]&0x80 != 0 {
			tag = (tag << 7) + int(tlv[tbytes]&0x7f)
			tbytes++
		}
		tag = (tag << 7) + int(tlv[tbytes]&0x7f)
		tbytes++
	}
	if tlv[tbytes]&0x80 == 0 {
		length = int(tlv[tbytes] & 0x7f)
	} else {
		lbytes = int(tlv[tbytes] & 0x7f)
		if lbytes == 0 {
			value = nil
			return
		}
		for count := 0; count < lbytes; count++ {
			length = (length << 8) + int(tlv[tbytes+1+count]&0xff)
		}
		lbytes++
	}
	if len(tlv) != tbytes+lbytes+length {
		value = nil
		return
	}
	value = tlv[(tbytes + lbytes):]
	return
}

func bindingsToCBindings(bindings *ChannelBindings) (cbindings C.gss_channel_bindings_t) {
	if bindings == nil {
		return nil
	}
	cbindings.application_data = bytesToBuffer(bindings.ApplicationData)
	return
}

func flagsToFlags(flags C.OM_uint32) (recFlags Flags) {
	if flags&C.GSS_C_DELEG_FLAG != 0 {
		recFlags.Deleg = true
	}
	if flags&C.GSS_C_DELEG_POLICY_FLAG != 0 {
		recFlags.DelegPolicy = true
	}
	if flags&C.GSS_C_MUTUAL_FLAG != 0 {
		recFlags.Mutual = true
	}
	if flags&C.GSS_C_REPLAY_FLAG != 0 {
		recFlags.Replay = true
	}
	if flags&C.GSS_C_SEQUENCE_FLAG != 0 {
		recFlags.Sequence = true
	}
	if flags&C.GSS_C_ANON_FLAG != 0 {
		recFlags.Anon = true
	}
	if flags&C.GSS_C_CONF_FLAG != 0 {
		recFlags.Conf = true
	}
	if flags&C.GSS_C_INTEG_FLAG != 0 {
		recFlags.Integ = true
	}
	if flags&C.GSS_C_TRANS_FLAG != 0 {
		recFlags.Trans = true
	}
	if flags&C.GSS_C_PROT_READY_FLAG != 0 {
		recFlags.ProtReady = true
	}
	return
}

func flagsToInt(flags Flags) (recFlags C.OM_uint32) {
	if flags.Deleg {
		recFlags |= C.GSS_C_DELEG_FLAG
	}
	if flags.DelegPolicy {
		recFlags |= C.GSS_C_DELEG_POLICY_FLAG
	}
	if flags.Mutual {
		recFlags |= C.GSS_C_MUTUAL_FLAG
	}
	if flags.Replay {
		recFlags |= C.GSS_C_REPLAY_FLAG
	}
	if flags.Sequence {
		recFlags |= C.GSS_C_SEQUENCE_FLAG
	}
	if flags.Anon {
		recFlags |= C.GSS_C_ANON_FLAG
	}
	if flags.Conf {
		recFlags |= C.GSS_C_CONF_FLAG
	}
	if flags.Integ {
		recFlags |= C.GSS_C_INTEG_FLAG
	}
	if flags.Trans {
		recFlags |= C.GSS_C_TRANS_FLAG
	}
	if flags.ProtReady {
		recFlags |= C.GSS_C_PROT_READY_FLAG
	}
	return
}

func InitSecContext(claimantCredHandle CredHandle, contextHandle *ContextHandle, targName InternalName, mechType asn1.ObjectIdentifier, reqFlags Flags, lifetimeReq uint32, chanBindings *ChannelBindings, inputToken []byte) (majorStatus, minorStatus uint32, mechTypeRec asn1.ObjectIdentifier, outputToken []byte, recFlags Flags, transState, protReadyState bool, lifetimeRec uint32) {
	handle := C.gss_cred_id_t(claimantCredHandle)
	ctx := C.gss_ctx_id_t(*contextHandle)
	name := C.gss_name_t(targName)
	desired := oidToCOid(mechType)
	flags := flagsToInt(reqFlags)
	lifetime := C.OM_uint32(lifetimeReq)
	bindings := bindingsToCBindings(chanBindings)
	var major, minor C.OM_uint32
	var itoken, otoken C.gss_buffer_desc
	var actual C.gss_OID

	if inputToken != nil {
		itoken = bytesToBuffer(inputToken)
	}

	major = C.gss_init_sec_context(&minor, handle, &ctx, name, desired, flags, lifetime, bindings, &itoken, &actual, &otoken, &flags, &lifetime)
	C.free_oid(desired)

	*contextHandle = ContextHandle(ctx)
	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if actual != nil {
		mechTypeRec = coidToOid(*actual)
		/* actual is read-only, so don't free it */
	}
	if otoken.length > 0 {
		outputToken = bufferToBytes(otoken)
		major = C.gss_release_buffer(&minor, &otoken)
	}
	recFlags = flagsToFlags(flags)
	if flags&C.GSS_C_TRANS_FLAG != 0 {
		transState = true
	}
	if flags&C.GSS_C_PROT_READY_FLAG != 0 {
		protReadyState = true
	}
	lifetimeRec = uint32(lifetime)
	return
}

func bufferToBytes(cdesc C.gss_buffer_desc) (b []byte) {
	length := C.int(cdesc.length)

	b = C.GoBytes(cdesc.value, length)
	return
}

func GetMIC(contextHandle ContextHandle, qopReq uint32, message []byte) (majorStatus, minorStatus uint32, perMessageToken []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	qop := C.gss_qop_t(qopReq)
	var msg, mic C.gss_buffer_desc
	var major, minor C.OM_uint32

	msg = bytesToBuffer(message)

	major = C.gss_get_mic(&minor, handle, qop, &msg, &mic)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if mic.length > 0 {
		perMessageToken = bufferToBytes(mic)
		major = C.gss_release_buffer(&minor, &mic)
	}
	return
}
