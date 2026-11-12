package targetidentity

import "testing"

func TestMappedImageAmbiguityAndPartialZeroFillConflict(t *testing.T) {
	m := &MappedImage{body: make([]byte, 16), Regions: []ImageRegion{{"one", 0x1000, 0, 8, 32}, {"two", 0x1004, 8, 4, 4}}}
	if _, _, err := m.FileBytes(0x1004, 4); err == nil {
		t.Fatal("ambiguous mapping accepted")
	}
	if _, _, err := m.FileBytes(0x1000, 8); err == nil {
		t.Fatal("partially overlapping mapping accepted")
	}
	m.Regions[1] = ImageRegion{"partial-file-conflict", 0x1014, 8, 4, 4}
	if m.ZeroFill(0x1010, 16) {
		t.Fatal("partial file overlap treated as zero fill")
	}
	m.Regions = m.Regions[:1]
	if !m.ZeroFill(0x1010, 16) {
		t.Fatal("declared zero fill lost")
	}
	if _, _, err := m.FileBytes(^uint64(0), 2); err == nil {
		t.Fatal("virtual wraparound accepted")
	}
}
