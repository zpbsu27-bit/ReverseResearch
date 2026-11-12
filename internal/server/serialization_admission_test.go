package server

import "testing"

func TestStaticSerializationUsesExistingResourceAdmission(t *testing.T) {
	for _, name := range []string{"app_tar_inspect", "app_zip_read", "app_javascript_application", "apple_plist_inspect", "apple_keyed_archive_inspect", "crash_core_inspect", "crash_core_note_read", "web_wasm_inspect"} {
		if got := resourceWeight(name); got != 8 {
			t.Fatalf("%s weight %d; bounded readers need the shared heavy admission", name, got)
		}
	}
	if resourceWeight("reverse_status") != 1 || resourceWeight("memscan") != globalResourceCapacity {
		t.Fatal("unrelated admission changed")
	}
}
