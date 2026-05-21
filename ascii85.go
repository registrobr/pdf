package pdf

// file with help function for ascii85 decoder
// later if new decoders is going to add it reasonable to rename file and add them here
// also create interfaces to switch between them (like in unidoc)

import (
	"io"
)

type alphaReader struct {
	reader io.Reader
}

func newAlphaReader(reader io.Reader) *alphaReader {
	return &alphaReader{reader: reader}
}

func checkASCII85(r byte) byte {
	if r >= '!' && r <= 'u' { // 33 <= ascii85 <=117
		return r
	}
	if r == '~' {
		return 1 // for marking possible end of data
	}
	return 0 // if non-ascii85
}

func (a *alphaReader) Read(p []byte) (int, error) {
	n, err := a.reader.Read(p)
	if err != nil {
		return n, err
	}

	// Filter in-place to avoid allocation
	writeIdx := 0
	tilda := false
	for i := 0; i < n; i++ {
		char := checkASCII85(p[i])
		if char == '>' && tilda { // end of data
			break
		}
		if char > 1 {
			p[writeIdx] = char
			writeIdx++
		}
		if char == 1 {
			tilda = true // possible end of data
		}
	}

	return writeIdx, nil
}
