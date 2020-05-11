package lockbox

import "darlinggo.co/version"

const nextVersion = "v0.1.0"

func getVersion() string {
	if version.Tag != "" {
		return version.Tag
	}
	if version.Hash != "" {
		return version.Hash
	}
	return nextVersion + "-dev"
}
