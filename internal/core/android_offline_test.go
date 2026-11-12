package core

import (
	"testing"

	"reverseresearch/internal/sandbox"
)

func TestAndroidOfflinePreparationDoesNotRequireDeviceTools(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range []string{
		"安卓离线 APK Manifest 和 resources.arsc 声明研究，查看 DEX 方法元数据并保留静态证据",
		"offline APK manifest and DEX metadata research",
	} {
		p, err := service.Prepare(task)
		if err != nil {
			t.Fatal(err)
		}
		if p.Route.Route.ID != "android-static" || p.Playbook == nil || p.Playbook.ID != "android-static" || p.Route.Classification.EffectClass != "observation" {
			t.Fatalf("offline task routing/playbook differs: %+v", p)
		}
		if !p.Capability.FullReady || !p.Capability.Runnable || p.Capability.CoveragePercent != 100 || len(p.Capability.Tools) != 0 || len(p.Provision.Items) != 0 {
			t.Fatalf("built-in offline route required external tools: %+v", p.Capability)
		}
		if p.Sandbox.Kind != sandbox.KindFilesystem || !p.Sandbox.Ready || len(p.Sandbox.MissingTools) != 0 {
			t.Fatalf("offline sandbox needs external host: %+v", p.Sandbox)
		}
	}
	fallback, err := service.CapabilityStatus("unclassified")
	if err != nil || fallback.Runnable || fallback.FullReady {
		t.Fatalf("unknown route gained built-in readiness: %+v %v", fallback, err)
	}
	device, err := service.Prepare("用 adb 连接 android 手机并通过 frida 跟踪 smali 执行")
	if err != nil || device.Route.Route.ID != "android" || device.Playbook == nil || device.Playbook.ID != "android" {
		t.Fatalf("runtime route changed: %+v %v", device, err)
	}
}
