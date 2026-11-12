package core

import (
	"context"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/dfir"
	"reverseresearch/internal/iosinspect"
	"reverseresearch/internal/webinspect"
)

func (s *Service) InspectApplication(path string, o appinspect.PageOptions) (appinspect.ApplicationReport, error) {
	return appinspect.InspectApplication(path, o)
}

func (s *Service) InspectWebHARAPI(path string, o webinspect.HAROptions) (webinspect.HARAPIReport, error) {
	return webinspect.InspectHARAPI(path, o)
}
func (s *Service) ReadWebHARBody(path string, o webinspect.HARBodyOptions) (webinspect.HARBodyReport, error) {
	return webinspect.ReadHARBody(path, o)
}
func (s *Service) CompareWebHAR(left, right string, o webinspect.HARCompareOptions) (webinspect.HARComparison, error) {
	return webinspect.CompareHAR(left, right, o)
}

func (s *Service) LocateWebSourceMap(path string, o webinspect.SourceMapLocateOptions) (webinspect.SourceMapLocation, error) {
	return webinspect.LocateSourceMap(path, o)
}
func (s *Service) InspectASAR(path string, o appinspect.PageOptions) (appinspect.ASARReport, error) {
	return appinspect.InspectASAR(path, o)
}
func (s *Service) ReadASAR(path string, o appinspect.EntryReadOptions) (appinspect.ASARReadReport, error) {
	return appinspect.ReadASAR(path, o)
}
func (s *Service) InspectJavaScript(path string, o appinspect.JavaScriptOptions) (appinspect.JavaScriptReport, error) {
	return appinspect.InspectJavaScript(path, o)
}
func (s *Service) InspectManaged(path string, o appinspect.PageOptions) (appinspect.ManagedReport, error) {
	return appinspect.InspectManaged(path, o)
}
func (s *Service) InspectManagedMethod(path string, o appinspect.ManagedMethodOptions) (appinspect.ManagedMethodReport, error) {
	return appinspect.InspectManagedMethod(path, o)
}

func (s *Service) InspectGoBinary(path string, o appinspect.PageOptions) (appinspect.GoBinaryReport, error) {
	return appinspect.InspectGoBinary(path, o)
}
func (s *Service) ReadGoMetadata(path string, o appinspect.GoMetadataOptions) (appinspect.GoMetadataReport, error) {
	return appinspect.ReadGoMetadata(path, o)
}
func (s *Service) InspectEVM(ctx context.Context, path string, o appinspect.EVMOptions) (appinspect.EVMReport, error) {
	return appinspect.InspectEVM(ctx, path, o)
}
func (s *Service) InspectZIP(path string, o appinspect.PageOptions) (appinspect.ZIPReport, error) {
	return appinspect.InspectZIP(path, o)
}
func (s *Service) ReadZIP(path string, o appinspect.EntryReadOptions) (appinspect.ZIPReadReport, error) {
	return appinspect.ReadZIP(path, o)
}
func (s *Service) CompareJavaScript(left, right string, o appinspect.CompareOptions) (appinspect.StaticComparison, error) {
	return appinspect.CompareJavaScript(left, right, o)
}
func (s *Service) CompareManaged(left, right string, o appinspect.CompareOptions) (appinspect.StaticComparison, error) {
	return appinspect.CompareManaged(left, right, o)
}

func (s *Service) InspectTAR(path string, o appinspect.PageOptions) (appinspect.TARReport, error) {
	return appinspect.InspectTAR(path, o)
}

func (s *Service) InspectApplicationPackage(path string, o appinspect.PackageOptions) (appinspect.PackageReport, error) {
	return appinspect.InspectPackage(path, o)
}

func (s *Service) InspectDEX(path string, o appinspect.DEXOptions) (appinspect.DEXReport, error) {
	return appinspect.InspectDEX(path, o)
}

func (s *Service) RecoverAndroid(ctx context.Context, path string, o appinspect.AndroidRecoveryOptions) (appinspect.AndroidRecoveryReport, error) {
	return appinspect.RecoverAndroid(ctx, s.root, path, o)
}
func (s *Service) ReadTAR(path string, o appinspect.EntryReadOptions) (appinspect.TARReadReport, error) {
	return appinspect.ReadTAR(path, o)
}
func (s *Service) InspectApplePlist(path string, o iosinspect.InspectOptions) (iosinspect.PlistReport, error) {
	return iosinspect.InspectPlist(path, o)
}
func (s *Service) ReadApplePlistData(path string, o iosinspect.PlistDataOptions) (iosinspect.PlistDataReport, error) {
	return iosinspect.ReadPlistData(path, o)
}
func (s *Service) InspectAppleKeyedArchive(path string, o iosinspect.KeyedArchiveOptions) (iosinspect.KeyedArchiveReport, error) {
	return iosinspect.InspectKeyedArchive(path, o)
}
func (s *Service) InspectAppleNIB(path string, o iosinspect.NIBOptions) (iosinspect.NIBReport, error) {
	return iosinspect.InspectNIB(path, o)
}
func (s *Service) InspectRecordedCore(path string, o dfir.CoreOptions) (dfir.CoreReport, error) {
	return dfir.InspectRecordedCore(path, o)
}
func (s *Service) ReadRecordedCoreNote(path string, o dfir.CoreNoteReadOptions) (dfir.CoreNoteReadReport, error) {
	return dfir.ReadCoreNote(path, o)
}
