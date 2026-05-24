package platform

import "testing"

func TestOSCapabilityHelpers(t *testing.T) {
	cases := []struct {
		name     string
		os       OS
		mac      bool
		launchd  bool
		systemd  bool
		registry bool
		common   bool
	}{
		{name: "darwin", os: OSDarwin, mac: true, launchd: true, common: true},
		{name: "linux", os: OSLinux, systemd: true, common: true},
		{name: "windows", os: OSWindows, registry: true, common: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.os.SupportsMacOSSecuritySettings(); got != tc.mac {
				t.Fatalf("macOS settings capability = %t, want %t", got, tc.mac)
			}
			if got := tc.os.SupportsLaunchdPersistence(); got != tc.launchd {
				t.Fatalf("launchd capability = %t, want %t", got, tc.launchd)
			}
			if got := tc.os.SupportsLinuxSystemd(); got != tc.systemd {
				t.Fatalf("systemd capability = %t, want %t", got, tc.systemd)
			}
			if got := tc.os.SupportsWindowsRegistry(); got != tc.registry {
				t.Fatalf("registry capability = %t, want %t", got, tc.registry)
			}
			if got := tc.os.SupportsCommonFilesystemChecks(); got != tc.common {
				t.Fatalf("common filesystem capability = %t, want %t", got, tc.common)
			}
		})
	}
}
