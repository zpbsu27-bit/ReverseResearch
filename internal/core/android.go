package core

import (
	"context"
	"fmt"

	"reverseresearch/internal/androidinspect"
)

func (s *Service) AndroidStatus() (androidinspect.RuntimeStatus, error) {
	index, err := s.ScanTools()
	if err != nil {
		return androidinspect.RuntimeStatus{}, err
	}
	return androidinspect.Status(index), nil
}

func (s *Service) androidManager() (*androidinspect.Manager, error) {
	index, err := s.ScanTools()
	if err != nil {
		return nil, err
	}
	adb, ok := index.ByName("adb")
	if !ok || !adb.Available {
		return nil, fmt.Errorf("adb runtime unavailable; install/configure adb and run tools scan")
	}
	return androidinspect.New(s.root, adb.Path)
}

func (s *Service) AndroidDevices(ctx context.Context) ([]androidinspect.Device, error) {
	manager, err := s.androidManager()
	if err != nil {
		return nil, err
	}
	return manager.Devices(ctx)
}

func (s *Service) ProbeAndroidDevice(ctx context.Context, serial string) (androidinspect.DeviceProbe, error) {
	manager, err := s.androidManager()
	if err != nil {
		return androidinspect.DeviceProbe{}, err
	}
	return manager.Probe(ctx, serial)
}

func (s *Service) PrepareAndroidWorkspace(serial string) (androidinspect.Workspace, error) {
	return androidinspect.PrepareWorkspace(s.root, serial)
}

func (s *Service) SnapshotAndroidUI(ctx context.Context, serial string) (androidinspect.Snapshot, error) {
	manager, err := s.androidManager()
	if err != nil {
		return androidinspect.Snapshot{}, err
	}
	return manager.Snapshot(ctx, serial)
}

func (s *Service) TapAndroidUI(ctx context.Context, request androidinspect.TapRequest) (androidinspect.TapReceipt, error) {
	manager, err := s.androidManager()
	if err != nil {
		return androidinspect.TapReceipt{}, err
	}
	return manager.Tap(ctx, request)
}
