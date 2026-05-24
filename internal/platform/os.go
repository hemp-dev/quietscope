package platform

import "runtime"

type OS string

const (
	OSDarwin  OS = "darwin"
	OSLinux   OS = "linux"
	OSWindows OS = "windows"
)

func CurrentOS() OS {
	return OS(runtime.GOOS)
}

func (os OS) IsDarwin() bool {
	return os == OSDarwin
}

func (os OS) IsLinux() bool {
	return os == OSLinux
}

func (os OS) IsWindows() bool {
	return os == OSWindows
}

func IsDarwin() bool {
	return CurrentOS().IsDarwin()
}

func IsLinux() bool {
	return CurrentOS().IsLinux()
}

func IsWindows() bool {
	return CurrentOS().IsWindows()
}

func SupportsMacOSSecuritySettings() bool {
	return CurrentOS().SupportsMacOSSecuritySettings()
}

func SupportsLaunchdPersistence() bool {
	return CurrentOS().SupportsLaunchdPersistence()
}

func SupportsLinuxSystemd() bool {
	return CurrentOS().SupportsLinuxSystemd()
}

func SupportsWindowsRegistry() bool {
	return CurrentOS().SupportsWindowsRegistry()
}

func SupportsCommonFilesystemChecks() bool {
	return CurrentOS().SupportsCommonFilesystemChecks()
}

func (os OS) SupportsMacOSSecuritySettings() bool {
	return os.IsDarwin()
}

func (os OS) SupportsLaunchdPersistence() bool {
	return os.IsDarwin()
}

func (os OS) SupportsLinuxSystemd() bool {
	return os.IsLinux()
}

func (os OS) SupportsWindowsRegistry() bool {
	return os.IsWindows()
}

func (os OS) SupportsCommonFilesystemChecks() bool {
	return true
}
