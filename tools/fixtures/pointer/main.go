package main

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"unsafe"
)

const (
	firstOffset  = uintptr(0x10)
	secondOffset = uintptr(0x20)
)

var (
	targetValue uint64 = 0x1122334455667788
	midValue    uintptr
	rootValue   uintptr
)

type report struct {
	PID             int      `json:"pid"`
	RootSlotAddress uint64   `json:"root_slot_address"`
	MidSlotAddress  uint64   `json:"mid_slot_address"`
	TargetAddress   uint64   `json:"target_address"`
	ScanStart       uint64   `json:"scan_start"`
	ScanEnd         uint64   `json:"scan_end"`
	Offsets         []uint64 `json:"offsets"`
	TargetValue     uint64   `json:"target_value"`
}

func main() {
	target := uintptr(unsafe.Pointer(&targetValue))
	midSlot := uintptr(unsafe.Pointer(&midValue))
	rootSlot := uintptr(unsafe.Pointer(&rootValue))
	midValue = target - secondOffset
	rootValue = midSlot - firstOffset

	minimum := rootSlot
	if midSlot < minimum {
		minimum = midSlot
	}
	if target < minimum {
		minimum = target
	}
	maximum := rootSlot
	if midSlot > maximum {
		maximum = midSlot
	}
	if target > maximum {
		maximum = target
	}
	const page = uintptr(4096)
	start := minimum &^ (page - 1)
	end := (maximum + page) &^ (page - 1)
	if end <= maximum {
		end = maximum + page
	}

	if err := json.NewEncoder(os.Stdout).Encode(report{
		PID:             os.Getpid(),
		RootSlotAddress: uint64(rootSlot),
		MidSlotAddress:  uint64(midSlot),
		TargetAddress:   uint64(target),
		ScanStart:       uint64(start),
		ScanEnd:         uint64(end),
		Offsets:         []uint64{uint64(firstOffset), uint64(secondOffset)},
		TargetValue:     targetValue,
	}); err != nil {
		panic(err)
	}
	runtime.KeepAlive(&targetValue)
	runtime.KeepAlive(&midValue)
	runtime.KeepAlive(&rootValue)

	scanner := bufio.NewScanner(os.Stdin)
	_ = scanner.Scan()
}
