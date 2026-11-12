package main

import (
	"encoding/json"
	"os"
	"sync/atomic"
	"time"
	"unsafe"
)

const initialValue uint32 = 0x11223344

var marker uint32 = initialValue

func main() {
	info := struct {
		PID     int    `json:"pid"`
		Address string `json:"address"`
		Value   uint32 `json:"value"`
	}{
		PID:     os.Getpid(),
		Address: formatAddress(uintptr(unsafe.Pointer(&marker))),
		Value:   atomic.LoadUint32(&marker),
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(info); err != nil {
		os.Exit(2)
	}
	for {
		_ = atomic.LoadUint32(&marker)
		time.Sleep(100 * time.Millisecond)
	}
}

func formatAddress(address uintptr) string {
	const digits = "0123456789ABCDEF"
	if address == 0 {
		return "0"
	}
	var buffer [16]byte
	index := len(buffer)
	for address != 0 {
		index--
		buffer[index] = digits[address&0xF]
		address >>= 4
	}
	return string(buffer[index:])
}
