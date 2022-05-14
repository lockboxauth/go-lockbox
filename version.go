package lockbox

import (
	"runtime/debug"
)

var versionOverride string

func getVersion() string {
	if versionOverride != "" {
		return versionOverride
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, m := range info.Deps {
		if m.Path != "lockbox.dev/go-lockbox" {
			continue
		}
		if m.Replace == nil {
			return m.Version
		}
		return "replaced"
	}
	if info.Main.Path != "lockbox.dev/go-lockbox" {
		return "unknown"
	}
	return info.Main.Version
}
