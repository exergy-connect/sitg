// Package scenarios contains traffic scenarios embedded in the SITG binary.
package scenarios

import _ "embed"

// ArtificialTango is the traffic choreography for Artificial Tango.
//
//go:embed artificial-tango.txt
var ArtificialTango string

// ArtificialTangoArgs supplies animation defaults before the caller's CLI flags.
// Explicit CLI values override these defaults through normal flag parsing.
func ArtificialTangoArgs(cli []string) []string {
	return append([]string{"--rate", "2pps", "--pkt-size", "1200"}, cli...)
}
