package tools

/*
#cgo LDFLAGS: -lws2_32 -liphlpapi
#include <stdlib.h>
#include "send_arp.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

func ShowMac(ip string) (result string, err error) {
	ipString := C.CString(ip)
	macString := C.CString("000000000000000000000000")

	ret := C.GetMacByARP(ipString, macString)

	if ret == 0 {
		result = C.GoString(macString)
		err = nil
	} else {
		result = ""
		err = errors.New("SendARP Failed")
	}

	C.free(unsafe.Pointer(ipString))
	C.free(unsafe.Pointer(macString))

	return result, err
}
