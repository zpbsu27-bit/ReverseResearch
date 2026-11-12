package modules

import (
	"errors"
	"testing"

	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/targetidentity"
)

func leaseForPE(bits int, machine string) processcontrol.Lease {
	return processcontrol.Lease{
		Identity: processcontrol.Identity{
			Image: targetidentity.Identity{
				Format: "pe",
				PE:     &targetidentity.PEIdentity{Bits: bits, Machine: machine},
			},
		},
	}
}

func TestXDBGBitsFromLeaseRoutesOnlySupportedPEArchitectures(t *testing.T) {
	for _, test := range []struct {
		name    string
		lease   processcontrol.Lease
		want    int
		wantErr bool
	}{
		{name: "x86", lease: leaseForPE(32, "i386"), want: 32},
		{name: "x64", lease: leaseForPE(64, "amd64"), want: 64},
		{name: "arm64", lease: leaseForPE(64, "arm64"), wantErr: true},
		{name: "bit_mismatch", lease: leaseForPE(32, "amd64"), wantErr: true},
		{name: "non_pe", lease: processcontrol.Lease{}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := xdbgBitsFromLease(test.lease)
			if test.wantErr {
				if !errors.Is(err, ErrXDBGArchitectureUnsupported) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got=%d err=%v want=%d", got, err, test.want)
			}
		})
	}
}
