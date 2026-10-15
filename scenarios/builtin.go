// Package scenarios contains traffic scenarios embedded in the SITG binary.
package scenarios

import _ "embed"

// ArtificialTango is the traffic choreography for Artificial Tango.
//
//go:embed artificial-tango.txt
var ArtificialTango string
