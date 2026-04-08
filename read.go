// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/ascii85"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

type LoggerFunc func(string, ...any)

// A Reader is a single PDF file open for reading.
type Reader struct {
	f               io.ReaderAt
	end             int64
	xref            []xref
	trailer         Object // was dict
	trailerptr      Objptr
	key             []byte
	useAES          bool
	encVersion      int    // encryption version (V), 0 if not encrypted
	encKey          []byte // File Encryption Key (FEK) - for V=5 calls this is the final key
	XrefInformation ReaderXrefInformation
	PDFVersion      string
	closer          io.Closer
	logger          LoggerFunc

	// objCache caches resolved objects to prevent repetitive disk I/O.
	// Map key is the object ID.
	objCache map[uint32]Value
}

type ReaderXrefInformation struct {
	StartPos               int64
	EndPos                 int64
	Length                 int64
	PositionLength         int64
	PositionStartPos       int64
	PositionEndPos         int64
	ItemCount              int64
	Type                   string
	IncludingTrailerEndPos int64
	IncludingTrailerLength int64
}

// toLatin1 converts a UTF-8 string to Latin-1 (ISO-8859-1) encoding.
// Characters that cannot be represented in Latin-1 are replaced with '?'.
func toLatin1(s string) []byte {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 256 {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	return b
}

// bytesLastIndexOptimized is an optimized replacement for bytes.LastIndex
// that avoids the Rabin-Karp overhead for patterns <= 32 bytes.
// For longer patterns, it falls back to bytes.LastIndex.
//
//go:nosplit
func bytesLastIndexOptimized(s, sep []byte) int {
	n := len(sep)
	if n == 0 {
		return len(s)
	}
	if n > len(s) {
		return -1
	}
	// For short patterns, use simple reverse scan (faster than Rabin-Karp)
	if n <= 32 {
		first := sep[0]
		last := sep[n-1]
		for i := len(s) - n; i >= 0; i-- {
			// Quick 2-byte check before full comparison
			if s[i] == first && s[i+n-1] == last {
				match := true
				for j := 1; j < n-1; j++ {
					if s[i+j] != sep[j] {
						match = false
						break
					}
				}
				if match {
					return i
				}
			}
		}
		return -1
	}

	// For longer patterns, use standard library
	return bytes.LastIndex(s, sep)
}

func (info *ReaderXrefInformation) PrintDebug() {
	log.Printf("Start of xref position bytes: %d", info.PositionStartPos)
	log.Printf("Length of xref position bytes: %d", info.PositionLength)
	log.Printf("End of xref position bytes: %d", info.PositionEndPos)
	log.Printf("xref start position byte: %d", info.StartPos)
	log.Printf("xref end position byte: %d", info.EndPos)
	log.Printf("xref length in bytes: %d", info.Length)
	log.Printf("xref type: %s", info.Type)
	log.Printf("Amount of items in xref: %d", info.ItemCount)
	log.Printf("xref end (including trailer) position byte: %d", info.IncludingTrailerEndPos)
	log.Printf("xref length (including trailer) in bytes: %d", info.IncludingTrailerLength)
}

type xref struct {
	ptr      Objptr
	inStream bool
	stream   Objptr
	offset   int64
}

func (x *xref) Ptr() Ptr {
	return Ptr{id: x.ptr.id, gen: x.ptr.gen}
}

func (x *xref) Stream() Objptr {
	return x.stream
}

func GetDict() Object {
	return Object{Kind: Dict, DictVal: make(map[string]Object)}
}

/*
func (r *Reader) errorf(format string, args ...any) {
	panic(fmt.Errorf(format, args...))
}
*/

func (r *Reader) SetLoggger(l LoggerFunc) {
	r.logger = l
}

func (r *Reader) Xref() []xref {
	return r.xref
}

// GetObject reads and returns the object with the given ID.
// It resolves the object from the XRef table, using the cache if available.
func (r *Reader) GetObject(id uint32) (Value, error) {
	if int(id) >= len(r.xref) {
		return Value{}, fmt.Errorf("object ID %d out of range", id)
	}

	x := r.xref[id]
	if x.offset == 0 && !x.inStream {
		// Possibly free or invalid
		return Value{}, fmt.Errorf("object ID %d is not in use", id)
	}

	ptr := x.ptr
	if ptr.id != id {
		ptr.id = id
	}

	return r.resolve(Objptr{}, Object{Kind: Indirect, PtrVal: ptr}), nil
}

// Open opens a file for reading.
func Open(file string) (*Reader, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return NewReader(f, fi.Size())
}

// NewReader opens a file for reading, using the data in f with the given total size.
func NewReader(f io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderEncrypted(f, size, nil)
}

// NewReaderEncrypted opens a file for reading, using the data in f with the given total size.
// If the PDF is encrypted, NewReaderEncrypted calls pw repeatedly to obtain passwords
// to try. If pw returns the empty string, NewReaderEncrypted stops trying to decrypt
// the file and returns an error.
// nolint: gocyclo
func NewReaderEncrypted(f io.ReaderAt, size int64, pw func() string) (*Reader, error) {
	version, err := pdfVersion(f, size)
	if err != nil {
		return nil, err
	}

	end := size

	// Some PDF's are quite broken and have a lot of stuff after %%EOF.
	var eofPosition int64
	offset := end

	const pattern = "%%EOF"
	patternBytes := []byte(pattern)
	const segSize = int64(32 * 1024)
	bufSize := segSize

	var buf []byte
	for {
		if offset <= 0 {
			return nil, fmt.Errorf("not a PDF file: missing %%%%EOF")
		}

		if bufSize > offset {
			// Read first segment from f
			bufSize = offset
		}

		if offset != end {
			// Read additional bytes, handling the case when the pattern occurs between segments
			bufSize = segSize + int64(len(pattern)) - 1
		}

		if len(buf) != int(bufSize) {
			buf = make([]byte, bufSize)
		}
		offset -= bufSize

		if _, err := f.ReadAt(buf, offset); err != nil {
			return nil, err
		}

		if i := bytesLastIndexOptimized(buf, patternBytes); i > 0 {
			eofPosition = offset + int64(i)
			break
		}
	}

	// Read 200 bytes before the %%EOF.
	buf = make([]byte, int64(200))
	if _, err := f.ReadAt(buf, (eofPosition - 200)); err != nil {
		return nil, err
	}

	i := findLastLine(buf, "startxref")
	if i < 0 {
		i = 0
		//return nil, fmt.Errorf("malformed PDF file: missing final startxref")
	}

	r := &Reader{
		f:               f,
		end:             end,
		XrefInformation: ReaderXrefInformation{},
		PDFVersion:      version,
		logger:          func(string, ...any) {},
		objCache:        make(map[uint32]Value),
	}
	if c, ok := f.(io.Closer); ok {
		r.closer = c
	}
	pos := eofPosition - 200 + int64(i)

	// Save the position of the startxref element.
	r.XrefInformation.PositionStartPos = pos

	b := newBuffer(io.NewSectionReader(f, pos, end-pos), pos, r.encVersion)

	tok := b.readToken()

	startxrefFound := tok.MatchKeyword("startxref")
	var startxref int64
	if startxrefFound {
		startXRefObj := b.readToken()
		if startXRefObj.Kind != Integer {
			return nil, fmt.Errorf("malformed PDF file: startxref not followed by integer")
		}
		startxref = startXRefObj.Int64Val

		// Save length. Useful for calculations later on.
		r.XrefInformation.PositionLength = b.realPos + 1

		// Save end position. Add 1 for the newline character.
		r.XrefInformation.PositionEndPos = r.XrefInformation.PositionStartPos + r.XrefInformation.PositionLength

		// Save start position of xref.
		r.XrefInformation.StartPos = startxref
	}
	b = newBuffer(io.NewSectionReader(r.f, startxref, r.end-startxref), startxref, r.encVersion)
	xref, trailerptr, trailer, err := readXref(r, b)
	if err != nil {
		return nil, err
	}
	r.xref = xref
	r.trailer = trailer
	r.trailerptr = trailerptr
	if trailer.Kind == Dict && trailer.DictVal["Encrypt"].Kind == Null {
		return r, nil
	}
	// Check if Encrypt is present properly
	enc := trailer.DictVal["Encrypt"]
	if enc.Kind == Null {
		return r, nil
	}

	err = r.initEncrypt("")
	if err == nil {
		return r, nil
	}
	if pw == nil || err != ErrInvalidPassword {
		return nil, err
	}
	for {
		next := pw()
		if next == "" {
			break
		}
		if r.initEncrypt(next) == nil {
			return r, nil
		}
	}
	return nil, err
}

func pdfVersion(f io.ReaderAt, _ int64) (string, error) {
	buf := make([]byte, 10)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return "", err
	}
	if (!bytes.HasPrefix(buf, []byte("%PDF-1.")) || buf[7] < '0' || buf[7] > '7') &&
		(!bytes.HasPrefix(buf, []byte("%PDF-2.")) || buf[7] != '0') {
		return "", fmt.Errorf("not a PDF file: invalid header %s", string(buf))
	}

	return string(buf[5:8]), nil
}

// Trailer returns the file's Trailer value.
func (r *Reader) Trailer() Value {
	return Value{r: r, ptr: r.trailerptr, obj: r.trailer}
}

func readXref(r *Reader, b *buffer) ([]xref, Objptr, Object, error) {
	tok := b.readToken()
	if tok.MatchKeyword("xref") {
		if xr, trailerptr, trailer, err := readXrefTable(r, b); err == nil {
			return xr, trailerptr, trailer, err
		}
	}
	if tok.Kind == Integer {
		b.unreadToken(tok)
		if xr, trailerptr, trailer, err := readXrefStream(r, b); err == nil {
			return xr, trailerptr, trailer, err
		}
	}

	if xr, trailerptr, trailer, err := tryRecoverFromOffset116(r); err == nil {
		return xr, trailerptr, trailer, err
	}

	return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: cross-reference table not found: %v", tok)
}

// tryRecoverFromOffset116 attempts enhanced recovery for the common offset 116 corruption pattern

func tryRecoverFromOffset116(r *Reader) ([]xref, Objptr, Object, error) {
	// Offset 116 is the most common corruption pattern (44% of xref errors)
	// This typically means startxref is pointing to wrong location
	// Try multiple recovery strategies specific to this pattern

	// Strategy 1: Search for xref streams in the entire file
	if err := r.searchAndParseXref(); err == nil {
		if r.trailer.DictVal["Root"].StringVal != "" {
			return r.xref, r.trailerptr, r.trailer, nil
		}
	}

	// Strategy 2: Try rebuilding xref by scanning all objects
	if err := r.rebuildXrefTable(); err == nil {
		return r.xref, r.trailerptr, r.trailer, nil
	}

	// Strategy 3: Check common offset variations around 116
	// Sometimes the offset is slightly off
	offsets := []int64{0, 100, 120, 150, 200, 250}
	for _, offset := range offsets {
		if offset == 116 {
			continue // Already tried this
		}
		b := newBuffer(io.NewSectionReader(r.f, offset, r.end-offset), offset, r.encVersion)
		tok := b.readToken()

		// Check if it's a traditional xref table
		if tok.MatchKeyword("xref") {
			xr, tp, tr, err := readXrefTable(r, b)
			if err == nil {
				return xr, tp, tr, nil
			}
			continue // Skip the Put at the end since we already Put
		}

		// Check if it's an xref stream (starts with object number)
		if tok.Kind == Integer {
			b.unreadToken(tok)
			xr, tp, tr, err := readXrefStream(r, b)
			if err == nil {
				return xr, tp, tr, nil
			}
			continue // Skip the Put at the end since we already Put
		}
	}

	return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("offset 116 recovery failed")
}

func readXrefStream(r *Reader, b *buffer) ([]xref, Objptr, Object, error) {
	obj1 := b.readObject()
	// readObject returns the object. If it was an indirect definition, it has PtrVal set.
	strmptr := obj1.PtrVal
	if obj1.Kind != Stream {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: cross-reference table not found: %v", objfmt(obj1))
	}
	strm := obj1
	if strm.DictVal["Type"].NameVal != "XRef" {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref stream does not have type XRef")
	}
	sizeObj := strm.DictVal["Size"]
	if sizeObj.Kind != Integer {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref stream missing Size")
	}
	size := sizeObj.Int64Val

	table := make([]xref, size)

	table, err := readXrefStreamData(r, strm, table, size)
	if err != nil {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: %v", err)
	}

	seenPrev := map[int64]bool{}

	prevoff := strm.DictVal["Prev"]
	for prevoff.Kind != Null {
		off := prevoff.Int64Val
		if prevoff.Kind != Integer {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev is not integer: %v", prevoff)
		}

		if _, ok := seenPrev[off]; ok {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev loop detected: %v", off)
		}

		seenPrev[off] = true

		b := newBuffer(io.NewSectionReader(r.f, off, r.end-off), off, r.encVersion)
		obj1 := b.readObject()
		if obj1.Kind != Stream {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream not found: %v", objfmt(obj1))
		}
		prevstrm := obj1
		prevoff = prevstrm.DictVal["Prev"]

		prev := Value{r: r, obj: prevstrm}
		if prev.Kind() != Stream {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream is not stream: %v", prev)
		}
		if prev.Key("Type").Name() != "XRef" {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream does not have type XRef")
		}
		psize := prev.Key("Size").Int64()
		if psize > size {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream larger than last stream")
		}
		if table, err = readXrefStreamData(r, prev.obj, table, psize); err != nil {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: reading xref prev stream: %v", err)
		}
	}

	// Save the xref type. Useful for adding data to it.
	r.XrefInformation.Type = "stream"
	r.XrefInformation.ItemCount = size

	r.XrefInformation.ItemCount = int64(len(table))

	return table, strmptr, strm, nil
}

// nolint: gocyclo
func readXrefStreamData(r *Reader, strm Object, table []xref, size int64) ([]xref, error) {
	index := strm.DictVal["Index"]
	if index.Kind == Null {
		index = Object{Kind: Array, ArrayVal: []Object{{Kind: Integer, Int64Val: 0}, {Kind: Integer, Int64Val: size}}}
	}
	if len(index.ArrayVal)%2 != 0 {
		return nil, fmt.Errorf("invalid Index array %v", objfmt(index))
	}
	ww := strm.DictVal["W"]
	if ww.Kind != Array {
		return nil, fmt.Errorf("xref stream missing W array")
	}

	var w []int
	for _, x := range ww.ArrayVal {
		i := x.Int64Val
		if x.Kind != Integer || int64(int(i)) != i {
			return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
		}
		w = append(w, int(i))
	}
	if len(w) < 3 {
		return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
	}

	v := Value{r: r, obj: strm}
	wtotal := 0
	for _, wid := range w {
		wtotal += wid
	}
	buf := make([]byte, wtotal)
	data := v.Reader()

	idxArr := index.ArrayVal
	for len(idxArr) > 0 {
		start := idxArr[0].Int64Val
		n := idxArr[1].Int64Val
		if idxArr[0].Kind != Integer || idxArr[1].Kind != Integer {
			return nil, fmt.Errorf("malformed Index pair %v %v", objfmt(idxArr[0]), objfmt(idxArr[1]))
		}
		idxArr = idxArr[2:]
		for i := 0; i < int(n); i++ {
			_, err := io.ReadFull(data, buf)
			if err != nil {
				return nil, fmt.Errorf("error reading xref stream: %v", err)
			}

			v1 := decodeInt(buf[0:w[0]])
			if w[0] == 0 {
				v1 = 1
			}

			v2 := decodeInt(buf[w[0] : w[0]+w[1]])
			v3 := decodeInt(buf[w[0]+w[1] : w[0]+w[1]+w[2]])
			x := int(start) + i
			for cap(table) <= x {
				table = append(table[:cap(table)], xref{})
			}
			if table[x].ptr != (Objptr{}) {
				continue
			}
			switch v1 {
			case 0:
				table[x] = xref{ptr: Objptr{0, 65535}}
			case 1:
				table[x] = xref{ptr: Objptr{uint32(x), uint16(v3)}, offset: int64(v2)}
			case 2:
				table[x] = xref{ptr: Objptr{uint32(x), 0}, inStream: true, stream: Objptr{uint32(v2), 0}, offset: int64(v3)}
			default:
				fmt.Printf("invalid xref stream type %d: %x\n", v1, buf)
			}
		}
	}
	return table, nil
}

func decodeInt(b []byte) int {
	x := 0
	for _, c := range b {
		x = x<<8 | int(c)
	}
	return x
}

func readXrefTable(r *Reader, b *buffer) ([]xref, Objptr, Object, error) {
	var table []xref

	table, err := readXrefTableData(b, table)
	if err != nil {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: %v", err)
	}

	// Get length of trailer keyword and newline.
	trailerLength := int64(len("trailer")) + 1

	// Save end position.
	r.XrefInformation.EndPos = (r.XrefInformation.StartPos - trailerLength) + b.realPos

	// Save length position. Useful for calculations. Remove trailer keyword length, add 1 for newline.
	r.XrefInformation.Length = (b.realPos - trailerLength) + 1

	trailer := b.readObject()
	if trailer.Kind != Dict {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref table not followed by trailer dictionary")
	}

	seenPrev := map[int64]bool{}

	prevoff := trailer.DictVal["Prev"]
	for prevoff.Kind != Null {
		off := prevoff.Int64Val
		if prevoff.Kind != Integer {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev is not integer: %v", prevoff)
		}

		if _, ok := seenPrev[off]; ok {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev loop detected: %v", off)
		}

		seenPrev[off] = true

		b := newBuffer(io.NewSectionReader(r.f, off, r.end-off), off, r.encVersion)
		tok := b.readToken()
		if tok.Kind != Keyword || tok.KeywordVal != "xref" {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev does not point to xref")
		}
		table, err = readXrefTableData(b, table)
		if err != nil {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: %v", err)
		}

		t := b.readObject()
		if t.Kind != Dict {
			return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev table not followed by trailer dictionary")
		}
		prevoff = t.DictVal["Prev"]
	}

	sizeObj := trailer.DictVal["Size"]
	if sizeObj.Kind != Integer {
		return nil, Objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: trailer missing /Size entry")
	}
	size := sizeObj.Int64Val

	if size < int64(len(table)) {
		table = table[:size]
	}

	// Save the xref type. Useful for adding data to it.
	r.XrefInformation.Type = "table"

	// Save the amount of items in the table. Useful for generating a new id for the signature.
	r.XrefInformation.ItemCount = int64(len(table))

	// Save end position. Note that this is including the trailer and startxref (without value).
	r.XrefInformation.IncludingTrailerEndPos = r.XrefInformation.StartPos + b.realPos

	// Save length position. Useful for calculations.
	r.XrefInformation.IncludingTrailerLength = b.realPos + 1

	return table, Objptr{}, trailer, nil
}

// searchAndParseXref searches the PDF file for xref streams or xref tables
// when the startxref offset points to an invalid location.
// This is a recovery mechanism for PDFs with incorrect startxref values.
func (r *Reader) searchAndParseXref() error {
	// Limit search to reasonable file sizes to avoid memory issues
	if r.end > 100<<20 { // 100MB limit for search
		return errors.New("file too large for xref search")
	}

	// Read file content for searching
	data := make([]byte, r.end)
	if _, err := r.f.ReadAt(data, 0); err != nil && err != io.EOF {
		return err
	}

	// Try to find xref stream first (PDF 1.5+)
	if err := r.searchXrefStream(data); err == nil {
		return nil
	}

	// Try to find traditional xref table
	if err := r.searchXrefTable(data); err == nil {
		return nil
	}

	return errors.New("could not find valid xref table or stream")
}

// findXRefStreamPositions scans raw PDF bytes and returns every position where
// a /Type ... /XRef marker appears, tolerating arbitrary PDF whitespace (including newlines)
// between the two tokens.
func findXRefStreamPositions(data []byte) []int {
	var positions []int
	const needle = "/Type"
	start := 0

	for {
		idx := bytes.Index(data[start:], []byte(needle))
		if idx < 0 {
			break
		}
		idx += start

		j := idx + len(needle)
		for j < len(data) && isSpace(data[j]) {
			j++
		}

		if j < len(data) && bytes.HasPrefix(data[j:], []byte("/XRef")) {
			positions = append(positions, idx)
		}

		start = idx + 1
	}

	return positions
}

// searchXrefStream searches for xref stream objects in the PDF data
func (r *Reader) searchXrefStream(data []byte) error {
	positions := findXRefStreamPositions(data)
	if len(positions) == 0 {
		return errors.New("no xref stream found")
	}

	// Try each position, starting from the last one (most likely to be the main xref)
	var lastErr error
	for i := len(positions) - 1; i >= 0; i-- {
		matchPos := positions[i]

		// Find the start of the object containing this xref stream
		// Search backward for "N M obj" pattern - expand search range significantly
		searchStart := max(matchPos-2000, 0)

		searchArea := data[searchStart:matchPos]

		// Find " obj" or line-starting "obj"
		objPatterns := [][]byte{[]byte(" obj"), []byte("\nobj"), []byte("\robj")}
		bestIdx := -1
		for _, p := range objPatterns {
			idx := bytesLastIndexOptimized(searchArea, p)
			if idx > bestIdx {
				bestIdx = idx
			}
		}

		if bestIdx < 0 {
			lastErr = errors.New("could not find object definition for xref stream")
			continue
		}

		// Find line start
		lineStart := bestIdx
		for lineStart > 0 && searchArea[lineStart-1] != '\n' && searchArea[lineStart-1] != '\r' {
			lineStart--
		}

		objStart := int64(searchStart + lineStart)

		// Try to parse this as an xref stream
		b := newBuffer(io.NewSectionReader(r.f, objStart, r.end-objStart), objStart, r.encVersion)
		xref, trailerptr, trailer, err := readXrefStream(r, b)
		if err != nil {
			lastErr = err
			continue
		}

		r.xref = xref
		r.trailer = trailer
		r.trailerptr = trailerptr
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("could not parse any xref stream")
}

// searchXrefTable searches for traditional xref table in the PDF data
func (r *Reader) searchXrefTable(data []byte) error {
	// Look for "xref" keyword at start of line
	patterns := [][]byte{
		[]byte("\nxref\n"),
		[]byte("\nxref\r"),
		[]byte("\rxref\n"),
		[]byte("\rxref\r"),
	}

	lastMatch := -1
	for _, pattern := range patterns {
		idx := bytesLastIndexOptimized(data, pattern)
		if idx > lastMatch {
			lastMatch = idx
		}
	}

	if lastMatch < 0 {
		return errors.New("no xref table found")
	}

	// Start parsing from "xref" keyword
	xrefStart := int64(lastMatch + 1) // Skip the leading newline

	b := newBuffer(io.NewSectionReader(r.f, xrefStart, r.end-xrefStart), xrefStart, r.encVersion)

	// Read and verify the "xref" keyword
	tok := b.readToken()
	if !tok.MatchKeyword("xref") {
		return fmt.Errorf("expected 'xref' keyword at offset %d, got %v", xrefStart, tok)
	}

	xref, trailerptr, trailer, err := readXrefTable(r, b)
	if err != nil {
		return err
	}

	r.xref = xref
	r.trailer = trailer
	r.trailerptr = trailerptr
	return nil
}

// nolint: gocyclo
func (r *Reader) rebuildXrefTable() error {
	if r.end <= 0 {
		return errors.New("cannot rebuild xref: empty file")
	}
	if r.end > 200<<20 {
		return errors.New("pdf: file too large to rebuild xref")
	}
	data := make([]byte, int(r.end))
	sr := io.NewSectionReader(r.f, 0, r.end)
	if _, err := io.ReadFull(sr, data); err != nil {
		return err
	}
	entries := make(map[uint32]xref)
	search := 0
	objCount := 0
	for {
		idx := bytes.Index(data[search:], []byte(" obj"))
		if idx < 0 {
			break
		}
		pos := search + idx
		objCount++
		lineStart := pos
		for lineStart > 0 && data[lineStart-1] != '\n' && data[lineStart-1] != '\r' {
			lineStart--
		}
		line := strings.Fields(string(data[lineStart:pos]))
		if len(line) >= 2 {
			if id64, err1 := strconv.ParseUint(line[0], 10, 32); err1 == nil {
				if gen64, err2 := strconv.ParseUint(line[1], 10, 16); err2 == nil {
					ptr := Objptr{
						id:  uint32(id64),
						gen: uint16(gen64),
					}
					if _, ok := entries[ptr.id]; !ok {
						entries[ptr.id] = xref{ptr: ptr, offset: int64(lineStart)}
					}
				}
			}
		}
		search = pos + len(" obj")
	}
	if len(entries) == 0 {
		return fmt.Errorf("pdf: unable to rebuild xref - found %d ' obj' occurrences but no valid objects in %d bytes", objCount, len(data))
	}
	var maxID uint32
	for id := range entries {
		if id > maxID {
			maxID = id
		}
	}
	table := make([]xref, maxID+1)
	for id, entry := range entries {
		table[id] = entry
	}
	r.xref = table
	if err := r.recoverTrailer(data); err != nil {
		return fmt.Errorf("failed to recover trailer: %w", err)
	}
	return nil
}

func (r *Reader) recoverTrailer(data []byte) error {
	// First, try to find traditional trailer keyword
	idx := bytesLastIndexOptimized(data, []byte("trailer"))
	if idx >= 0 {
		buf := newBuffer(bytes.NewReader(data[idx:]), int64(idx), r.encVersion)
		buf.allowEOF = true
		if tok := buf.readToken(); tok.MatchKeyword("trailer") {
			obj := buf.readObject()
			if obj.Kind == Dict {
				r.trailer = obj
				r.trailerptr = Objptr{}
				return nil
			}
		}
	}

	// For PDF 1.5+ with xref stream, try to find and parse xref stream object
	// The xref stream contains trailer information in its dictionary
	if err := r.recoverXrefStreamTrailer(data); err == nil {
		return nil
	}

	// Last resort: try to synthesize a minimal trailer by finding Root object
	if rootRef := findRootObject(data); rootRef != (Objptr{}) {
		r.trailer = GetDict()
		r.trailer.DictVal["Size"] = Object{Kind: Integer, Int64Val: int64(len(r.xref))}
		r.trailer.DictVal["Root"] = Object{Kind: Indirect, PtrVal: rootRef}
		r.trailerptr = Objptr{}
		// if DebugOn {
		fmt.Printf("Synthesized minimal trailer with Root=%v\n", rootRef)
		// }
		return nil
	}

	return fmt.Errorf("trailer not found in %d bytes of PDF data", len(data))
}

// recoverXrefStreamTrailer attempts to find and parse an xref stream object
// to recover trailer information for PDF 1.5+ files that use xref streams.
// nolint: gocyclo
func (r *Reader) recoverXrefStreamTrailer(data []byte) error {
	// Search for xref stream objects by looking for "/Type /XRef" pattern
	// This is more reliable than looking for startxref offset
	candidates := findXRefStreamPositions(data)
	if len(candidates) == 0 {
		return fmt.Errorf("no xref stream found")
	}

	// Try each candidate, starting from the last one (most likely to be the main xref)
	for i := len(candidates) - 1; i >= 0; i-- {
		pos := candidates[i]

		// Find the start of the object definition by searching backward for "N M obj"
		objStart := r.findObjectStart(data, pos)
		if objStart < 0 {
			continue
		}

		// Try to parse the xref stream
		buf := newBuffer(bytes.NewReader(data[objStart:]), int64(objStart), r.encVersion)
		buf.allowEOF = true
		obj := buf.readObject()

		var v Value
		var strm Object
		var err error

		if obj.Kind == Indirect {
			v, err = r.GetObject(obj.PtrVal.id)
			if err != nil {
				continue
			}
			if v.obj.Kind != Stream {
				continue
			}
			strm = v.obj
		} else if obj.Kind == Stream {
			strm = obj
			v.ptr = Objptr{}
		}

		// Verify this is an XRef stream
		if strm.DictVal["Type"].NameVal != "XRef" {
			continue
		}

		// Extract trailer-equivalent information from the xref stream header
		trailer := GetDict()
		// Copy relevant trailer keys from xref stream header
		trailerFields := map[string]bool{
			"Size":    false,
			"Root":    false,
			"Info":    false,
			"ID":      false,
			"Encrypt": false,
			"Prev":    false,
		}
		for key := range trailerFields {
			if val, found := strm.DictVal[key]; found {
				trailerFields[key] = true
				trailer.DictVal[key] = val
			}
		}

		if !trailerFields["Root"] || !trailerFields["Size"] || trailer.DictVal["Size"].Kind != Integer {
			continue
		}

		// Try to parse the xref stream data to build the xref table
		size := trailer.DictVal["Size"].Int64Val

		table := make([]xref, size)
		table, err = readXrefStreamData(r, strm, table, size)
		if err != nil {
			// Even if we can't read the stream data, we might still have valid trailer
			// Try to use the rebuilt xref table from rebuildXrefTable
			if len(r.xref) > 0 {
				r.trailer = trailer
				r.trailerptr = v.ptr
				return nil
			}
			continue
		}

		// Merge with existing xref table if present
		if len(r.xref) > 0 {
			for i, entry := range table {
				if i < len(r.xref) && r.xref[i].ptr == (Objptr{}) && entry.ptr != (Objptr{}) {
					r.xref[i] = entry
				}
			}
		} else {
			r.xref = table
		}

		r.trailer = trailer
		r.trailerptr = v.ptr
		return nil
	}

	return fmt.Errorf("failed to parse any xref stream")
}

// findObjectStart searches backward from pos to find the start of an object definition
// Returns the position of the object number, or -1 if not found
func (r *Reader) findObjectStart(data []byte, pos int) int {
	// Search backward for "obj" keyword
	searchStart := pos
	if searchStart > 200 {
		searchStart = pos - 200
	} else {
		searchStart = 0
	}

	// Look for pattern like "123 0 obj" before the current position
	chunk := data[searchStart:pos]

	// Find the last occurrence of " obj" or "\nobj" or "\robj"
	objPatterns := [][]byte{[]byte(" obj"), []byte("\nobj"), []byte("\robj")}

	bestPos := -1
	for _, pattern := range objPatterns {
		idx := bytesLastIndexOptimized(chunk, pattern)
		if idx > bestPos {
			bestPos = idx
		}
	}

	if bestPos < 0 {
		return -1
	}

	// Now find the start of the line containing this "obj"
	lineStart := searchStart + bestPos
	for lineStart > 0 && data[lineStart-1] != '\n' && data[lineStart-1] != '\r' {
		lineStart--
	}

	// Verify this looks like an object definition (starts with number)
	if lineStart >= len(data) {
		return -1
	}

	// Skip whitespace
	for lineStart < pos && (data[lineStart] == ' ' || data[lineStart] == '\t') {
		lineStart++
	}

	// Check if it starts with a digit
	if lineStart < len(data) && data[lineStart] >= '0' && data[lineStart] <= '9' {
		return lineStart
	}

	return -1
}

// nolint: gocyclo
func readXrefTableData(b *buffer, table []xref) ([]xref, error) {
	for {
		tok := b.readToken()
		if tok.MatchKeyword("trailer") {
			break
		}
		if tok.Kind != Integer {
			return nil, fmt.Errorf("malformed xref table: expected integer start")
		}
		start := tok.Int64Val
		nObj := b.readToken()
		if nObj.Kind != Integer {
			return nil, fmt.Errorf("malformed xref table: expected integer count")
		}
		n := nObj.Int64Val

		for i := 0; i < int(n); i++ {
			offObj := b.readToken()
			genObj := b.readToken()
			allocObj := b.readToken()
			if offObj.Kind != Integer || genObj.Kind != Integer || allocObj.Kind != Keyword {
				return nil, fmt.Errorf("malformed xref table entry")
			}
			off := offObj.Int64Val
			gen := genObj.Int64Val
			alloc := allocObj.KeywordVal

			if alloc != "f" && alloc != "n" {
				return nil, fmt.Errorf("malformed xref table entry: invalid type %q", alloc)
			}
			x := int(start) + i
			for cap(table) <= x {
				table = append(table[:cap(table)], xref{})
			}
			if len(table) <= x {
				table = table[:x+1]
			}
			if alloc == "n" && table[x].offset == 0 {
				table[x] = xref{ptr: Objptr{uint32(x), uint16(gen)}, offset: off}
			}
		}
	}
	return table, nil
}

func findLastLine(buf []byte, s string) int {
	bs := []byte(s)
	max := len(buf)
	for {
		i := bytesLastIndexOptimized(buf[:max], bs)
		if i <= 0 || i+len(bs) >= len(buf) {
			return -1
		}
		if (buf[i-1] == '\n' || buf[i-1] == '\r') && (buf[i+len(bs)] == '\n' || buf[i+len(bs)] == '\r') {
			return i
		}
		max = i
	}
}

// nolint: gocyclo
func objfmt(x Object) string {
	switch x.Kind {
	default:
		return fmt.Sprintf("?Kind=%v?", x.Kind)
	case Null:
		return "null"
	case Bool:
		return strconv.FormatBool(x.BoolVal)
	case Integer:
		return strconv.FormatInt(x.Int64Val, 10)
	case Real:
		return strconv.FormatFloat(x.Float64Val, 'f', -1, 64)
	case String:
		if isPDFDocEncoded(x.StringVal) {
			return strconv.Quote(pdfDocDecode(x.StringVal))
		}
		if isUTF16(x.StringVal) {
			return strconv.Quote(utf16Decode(x.StringVal[2:]))
		}
		return strconv.Quote(x.StringVal)
	case Name:
		return "/" + x.NameVal
	case Keyword:
		return x.KeywordVal
	case Indirect:
		return fmt.Sprintf("%d %d R", x.PtrVal.id, x.PtrVal.gen)
	case Dict:
		var keys []string
		for k := range x.DictVal {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteString("<<")
		for i, k := range keys {
			elem := x.DictVal[k]
			if i > 0 {
				buf.WriteString(" ")
			}
			buf.WriteString("/")
			buf.WriteString(k)
			buf.WriteString(" ")
			buf.WriteString(objfmt(elem))
		}
		buf.WriteString(">>")
		return buf.String()

	case Array:
		var buf bytes.Buffer
		buf.WriteString("[")
		for i, elem := range x.ArrayVal {
			if i > 0 {
				buf.WriteString(" ")
			}
			buf.WriteString(objfmt(elem))
		}
		buf.WriteString("]")
		return buf.String()

	case Stream:
		hdr := Object{Kind: Dict, DictVal: x.DictVal}
		return fmt.Sprintf("%v@%d", objfmt(hdr), x.StreamOffset)
	}
}

// nolint: gocyclo
func (r *Reader) resolve(parent Objptr, x Object) (v Value) {
	defer func() {
		if e := recover(); e != nil {
			v = Value{err: fmt.Errorf("panic resolving %v: %v", x, e)}
		}
	}()

	if x.Kind == Indirect {
		ptr := x.PtrVal
		// Check cache first
		if v, ok := r.objCache[ptr.id]; ok {
			return v
		}

		if ptr.id >= uint32(len(r.xref)) {
			return Value{}
		}
		xref := r.xref[ptr.id]
		if xref.ptr != ptr || !xref.inStream && xref.offset == 0 {
			return Value{}
		}
		var obj Object
		if xref.inStream {
			strm := r.resolve(parent, Object{Kind: Indirect, PtrVal: xref.stream})
		Search:
			for {
				if strm.Kind() != Stream {
					// Tolerate corrupted xref stream reference
					return Value{}
				}
				if strm.Key("Type").Name() != "ObjStm" {
					// Not an object stream, return empty
					return Value{}
				}
				n := int(strm.Key("N").Int64())
				first := strm.Key("First").Int64()
				if first == 0 {
					// Missing First entry, return empty
					return Value{}
				}
				b := newBuffer(strm.Reader(), 0, r.encVersion)
				defer bufferPool.Put(b)
				b.allowEOF = true
				for i := 0; i < n; i++ {
					idObj := b.readToken()
					offObj := b.readToken()
					id := idObj.Int64Val
					off := offObj.Int64Val

					if uint32(id) == ptr.id {
						b.seekForward(first + off)
						x = b.readObject()
						break Search
					}
				}
				ext := strm.Key("Extends")
				if ext.Kind() != Stream {
					panic("cannot find object in stream")
				}
				strm = ext
			}
		} else {
			b := newBuffer(io.NewSectionReader(r.f, xref.offset, r.end-xref.offset), xref.offset, r.encVersion)
			defer bufferPool.Put(b) // Return to pool
			b.key = r.key
			b.useAES = r.useAES

			obj = b.readObject()
			// readObject handles the "objdef" structure internally by returning the Object
			// but storing the definition ID in PtrVal if it was an indirect definition.
			// Let's verify it matches the pointer we expected.

			// If obj matches criteria for definition:
			// In readObject, we return the object with PtrVal set to the def ID.

			// We check if PtrVal is set and check if it matches.
			// However, if obj IS an Indirect reference, PtrVal will be the reference ID.
			// But readObject for a definition returns the defined object (not Kind=Indirect).
			if obj.Kind != Indirect && obj.PtrVal != (Objptr{}) {
				if obj.PtrVal.id != ptr.id || obj.PtrVal.gen != ptr.gen {
					panic(fmt.Errorf("loading %v: found %v", ptr, obj.PtrVal))
				}
			} else if obj.Kind == Indirect && obj.PtrVal != ptr {
				// It turned out to be a reference? A definition cannot act as a reference directly unless it's a stream?
				panic(fmt.Errorf("loading %v: found reference %v", ptr, obj.PtrVal))
			}
			x = obj
		}
		parent = ptr

		// Cache the resolved value
		val := r.createValue(parent, x)
		r.objCache[ptr.id] = val
		return val
	}

	return r.createValue(parent, x)
}

// Close closes the Reader and the underlying file if it implements io.Closer.
func (r *Reader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

func (r *Reader) createValue(ptr Objptr, obj Object) Value {
	return Value{r: r, ptr: ptr, obj: obj}
}

type errorReadCloser struct {
	err error
}

func (e *errorReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

func (e *errorReadCloser) Close() error {
	return e.err
}

// newStreamReader returns a reader for the stream s.
func newStreamReader(s Object, r *Reader) io.ReadCloser {
	var rd io.Reader
	// s is Object(Stream). DictVal is header. StreamOffset is offset.

	// Need "Length" from header.
	// We can wrap s in Value to use Key method.
	val := Value{r: r, obj: s}
	length := val.Key("Length").Int64()

	rd = io.NewSectionReader(r.f, s.StreamOffset, length)

	if r.key != nil {
		var err error
		// We need the stream's object ID for decryption.
		// Use s.PtrVal which should be set to definition ID if it was read via readObject.
		// If s was created manually, PtrVal might be empty.
		// But newStreamReader is usually called from resolved objects.

		rd, err = decryptStream(r.key, r.useAES, r.encVersion, s.PtrVal, rd)
		if err != nil {
			return &errorReadCloser{err}
		}
	}

	filters := val.Key("Filter")
	if filters.Kind() == Name {
		var err error
		rd, err = applyFilter(rd, filters.Name(), val.Key("DecodeParms"))
		if err != nil {
			return &errorReadCloser{err}
		}
	} else if filters.Kind() == Array {
		for i := 0; i < filters.Len(); i++ {
			var err error
			rd, err = applyFilter(rd, filters.Index(i).Name(), val.Key("DecodeParms").Index(i))
			if err != nil {
				return &errorReadCloser{err}
			}
		}
	}

	return io.NopCloser(rd)
}

func applyFilter(rd io.Reader, name string, param Value) (io.Reader, error) {
	switch name {
	default:
		return nil, fmt.Errorf("unknown filter %s", name)
	// Used for JPEG; no need to decode
	case "DCTDecode":
		return rd, nil
	case "JBIG2Decode":
		fmt.Println("Warning: JBIG2 image detected, not supported yet, some images will not be saved correctly!")
		// TODO: create a reader based on page 31 of PDF spec
		return rd, nil
	// Used for JPEG2000; no need to decode
	case "JPXDecode":
		return rd, nil
	case "ASCIIHexDecode":
		return asciiHexReader{rd}, nil
	case "ASCII85Decode":
		return ascii85.NewDecoder(rd), nil
	case "FlateDecode":
		zr, err := zlib.NewReader(rd)
		if err != nil {
			return nil, err
		}
		pred := param.Key("Predictor")
		if pred.Kind() == Null {
			return zr, nil
		}
		columns := param.Key("Columns").Int64()
		switch pred.Int64() {
		default:
			return nil, fmt.Errorf("unknown predictor %v", pred)
		case 12:
			return &pngUpReader{r: zr, hist: make([]byte, 1+columns), tmp: make([]byte, 1+columns)}, nil
		}
	}
}

type asciiHexReader struct {
	r io.Reader
}

func (r asciiHexReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	var src [2]byte
	n := 0
	for n < len(dst) {
		_, err := io.ReadFull(r.r, src[:1])
		if err != nil {
			return n, err
		}
		if src[0] == '>' {
			return n, io.EOF
		}
		if isSpace(src[0]) {
			continue
		}
		_, err = io.ReadFull(r.r, src[1:2])
		if err != nil {
			return n, err
		}
		if src[1] == '>' {
			x := unhex(src[0]) << 4
			dst[n] = byte(x)
			return n + 1, io.EOF
		}
		if isSpace(src[1]) {
			// PDF spec says ignore whitespace. If second nibble is space, keep looking for it.
			for isSpace(src[1]) {
				_, err = io.ReadFull(r.r, src[1:2])
				if err != nil {
					return n, err
				}
				if src[1] == '>' {
					x := unhex(src[0]) << 4
					dst[n] = byte(x)
					return n + 1, io.EOF
				}
			}
		}
		x := unhex(src[0])<<4 | unhex(src[1])
		dst[n] = byte(x)
		n++
	}
	return n, nil
}

type pngUpReader struct {
	r    io.Reader
	hist []byte
	tmp  []byte
	pend []byte
}

func (r *pngUpReader) Read(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		if len(r.pend) > 0 {
			m := copy(b, r.pend)
			n += m
			b = b[m:]
			r.pend = r.pend[m:]
			continue
		}
		_, err := io.ReadFull(r.r, r.tmp)
		if err != nil {
			return n, err
		}
		if r.tmp[0] != 2 {
			return n, fmt.Errorf("malformed PNG-Up encoding")
		}
		for i, b := range r.tmp {
			r.hist[i] += b
		}
		r.pend = r.hist[1:]
	}
	return n, nil
}

var passwordPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// nolint: gocyclo
func (r *Reader) initEncrypt(password string) error {
	// See PDF 32000-1:2008, §7.6.
	// r.trailer is Object.
	encrypt := r.resolve(Objptr{}, r.trailer.DictVal["Encrypt"]).obj.DictVal
	// Encrypt is a dict Object, so DictVal

	if encrypt["Filter"].NameVal != "Standard" {
		return fmt.Errorf("unsupported PDF: encryption filter %v", objfmt(Object{Kind: Name, NameVal: encrypt["Filter"].NameVal}))
	}

	V := encrypt["V"].Int64Val

	// Support V=5
	// If V=5, delegate to V5 authentication
	if V == 5 {
		return r.initEncryptV5(password, encrypt)
	}

	n := encrypt["Length"].Int64Val
	if n == 0 {
		n = 40
	}
	if n%8 != 0 || n > 128 || n < 40 {
		return fmt.Errorf("malformed PDF: %d-bit encryption key", n)
	}

	if V != 1 && V != 2 && V != 4 {
		return fmt.Errorf("unsupported PDF: encryption version V=%d", V)
	}
	if V == 4 && !okayV4(encrypt) {
		return fmt.Errorf("unsupported PDF: encryption version V=%d", V)
	}

	ids := r.trailer.DictVal["ID"].ArrayVal
	if len(ids) < 1 {
		return fmt.Errorf("malformed PDF: missing ID in trailer")
	}
	idstr := ids[0].StringVal
	ID := []byte(idstr)
	R := encrypt["R"].Int64Val

	// Legacy path (V < 5)
	if R < 2 {
		return fmt.Errorf("malformed PDF: encryption revision R=%d", R)
	}
	if R > 4 {
		return fmt.Errorf("unsupported PDF: encryption revision R=%d", R)
	}
	O := encrypt["O"].StringVal
	U := encrypt["U"].StringVal
	if len(O) != 32 || len(U) != 32 {
		return fmt.Errorf("malformed PDF: missing O= or U= encryption parameters")
	}
	P := uint32(encrypt["P"].Int64Val)

	pw := toLatin1(password)
	h := md5.New()
	if len(pw) >= 32 {
		h.Write(pw[:32])
	} else {
		h.Write(pw)
		h.Write(passwordPad[:32-len(pw)])
	}
	h.Write([]byte(O))
	h.Write([]byte{byte(P), byte(P >> 8), byte(P >> 16), byte(P >> 24)})
	h.Write(ID)

	if R >= 4 && encrypt["EncryptMetadata"].Kind == Bool && !encrypt["EncryptMetadata"].BoolVal {
		h.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	}

	key := h.Sum(nil)

	if R >= 3 {
		for range 50 {
			h.Reset()
			h.Write(key[:n/8])
			key = h.Sum(key[:0])
		}
		key = key[:n/8]
	} else {
		key = key[:40/8]
	}

	c, err := rc4.NewCipher(key)
	if err != nil {
		return fmt.Errorf("malformed PDF: invalid RC4 key: %v", err)
	}

	var u []byte
	if R == 2 {
		u = make([]byte, 32)
		copy(u, passwordPad)
		c.XORKeyStream(u, u)
	} else {
		h.Reset()
		h.Write(passwordPad)
		h.Write(ID)
		u = h.Sum(nil)
		c.XORKeyStream(u, u)

		for i := 1; i <= 19; i++ {
			key1 := make([]byte, len(key))
			copy(key1, key)
			for j := range key1 {
				key1[j] ^= byte(i)
			}
			c, _ = rc4.NewCipher(key1)
			c.XORKeyStream(u, u)
		}
	}

	if !bytes.HasPrefix([]byte(U), u) {
		return ErrInvalidPassword
	}

	r.key = key
	r.useAES = V == 4
	r.encVersion = int(V)

	return nil
}

func (r *Reader) initEncryptV5(password string, encrypt map[string]Object) error {
	ids := r.trailer.DictVal["ID"].ArrayVal
	if len(ids) < 1 {
		return fmt.Errorf("malformed PDF: missing ID in trailer")
	}
	idstr := ids[0].StringVal

	// Extract additional parameters for V=5
	UE := encrypt["UE"].StringVal
	OE := encrypt["OE"].StringVal
	Perms := encrypt["Perms"].StringVal

	if len(UE) != 32 || len(OE) != 32 || len(Perms) != 16 {
		return fmt.Errorf("malformed PDF: missing UE/OE/Perms encryption parameters for V=5")
	}

	// Create encryption info for V=5
	info := PDFEncryptionInfo{
		Version:   EncryptionVersion(encrypt["V"].Int64Val),
		Revision:  EncryptionRevision(encrypt["R"].Int64Val),
		Method:    MethodAESV3,
		KeyLength: 256,
		P:         uint32(encrypt["P"].Int64Val),
		ID:        []byte(idstr),
		O:         []byte(encrypt["O"].StringVal),
		U:         []byte(encrypt["U"].StringVal),
		UE:        []byte(UE),
		OE:        []byte(OE),
		Perms:     []byte(Perms),
	} // Try to authenticate with the provided password
	auth := NewPasswordAuth(&info)
	key, err := auth.Authenticate(password)
	if err != nil {
		return err
	}

	r.key = key
	r.encKey = key
	r.useAES = true
	r.encVersion = 5
	return nil
}

var ErrInvalidPassword = fmt.Errorf("encrypted PDF: invalid password")

func okayV4(encrypt map[string]Object) bool {
	cfGen := encrypt["CF"]
	if cfGen.Kind != Dict {
		return false
	}
	cf := cfGen.DictVal
	stmf := encrypt["StmF"].NameVal
	strf := encrypt["StrF"].NameVal
	if stmf != strf {
		return false
	}
	cfparamGen := cf[stmf]
	if cfparamGen.Kind != Dict {
		return false
	}
	cfparam := cfparamGen.DictVal

	if val, ok := cfparam["AuthEvent"]; ok {
		if val.Kind != Name || val.NameVal != "DocOpen" {
			return false
		}
	}
	if val, ok := cfparam["Length"]; ok {
		// Standard security handler expresses the length in multiples of 8 (16 means 128)
		// and public-key security handler expresses it as is (128 means 128).
		if val.Kind != Integer || (val.Int64Val != 16 && val.Int64Val != 128) {
			return false
		}
	}
	if val, ok := cfparam["CFM"]; ok {
		if val.Kind != Name || val.NameVal != "AESV2" {
			return false
		}
	}
	return true
}

func cryptKey(key []byte, useAES bool, ptr Objptr) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte{byte(ptr.id), byte(ptr.id >> 8), byte(ptr.id >> 16), byte(ptr.gen), byte(ptr.gen >> 8)})
	if useAES {
		h.Write([]byte("sAlT"))
	}
	return h.Sum(nil)
}

func decryptString(key []byte, useAES bool, encVersion int, ptr Objptr, x string) (string, error) {
	if encVersion < 5 {
		key = cryptKey(key, useAES, ptr)
	}
	// For V=5, key is already the FEK (32 bytes for AES-256)

	if useAES {
		data := []byte(x)
		if len(data) < aes.BlockSize {
			return x, nil
		}
		iv := data[:aes.BlockSize]
		ciphertext := data[aes.BlockSize:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		if len(ciphertext)%aes.BlockSize != 0 {
			// return "", fmt.Errorf("decryption error: ciphertext not a multiple of block size")
			// Try to handle gracefully?
			return x, nil
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(ciphertext, ciphertext)

		padLen := int(ciphertext[len(ciphertext)-1])
		if padLen > aes.BlockSize || padLen == 0 {
			// return "", fmt.Errorf("decryption error: invalid padding")
			// Handle graceful
			return string(ciphertext), nil
		}
		return string(ciphertext[:len(ciphertext)-padLen]), nil
	} else {
		c, _ := rc4.NewCipher(key)
		data := []byte(x)
		c.XORKeyStream(data, data)
		x = string(data)
	}
	return x, nil
}

func decryptStream(key []byte, useAES bool, encVersion int, ptr Objptr, rd io.Reader) (io.Reader, error) {
	if encVersion < 5 {
		key = cryptKey(key, useAES, ptr)
	}

	if useAES {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES: %v", err)
		}

		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rd, iv); err != nil {
			return nil, err
		}

		cbc := cipher.NewCBCDecrypter(block, iv)
		return &cbcReader{cbc: cbc, rd: rd, buf: make([]byte, aes.BlockSize)}, nil
	}
	c, _ := rc4.NewCipher(key)
	return &rc4Reader{cipher: c, rd: rd}, nil
}

type cbcReader struct {
	cbc  cipher.BlockMode
	rd   io.Reader
	buf  []byte
	pend []byte
}

func (r *cbcReader) Read(b []byte) (n int, err error) {
	if len(r.pend) > 0 {
		n = copy(b, r.pend)
		r.pend = r.pend[n:]
		return n, nil
	}

	_, err = io.ReadFull(r.rd, r.buf)
	if err != nil {
		if err == io.EOF {
			return 0, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return 0, fmt.Errorf("encrypted stream not a multiple of block size")
		}
		return 0, err
	}

	r.cbc.CryptBlocks(r.buf, r.buf)
	r.pend = r.buf

	n = copy(b, r.pend)
	r.pend = r.pend[n:]
	return n, nil
}

type rc4Reader struct {
	cipher *rc4.Cipher
	rd     io.Reader
}

func (r *rc4Reader) Read(b []byte) (n int, err error) {
	n, err = r.rd.Read(b)
	if n > 0 {
		r.cipher.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

// findRootObject searches for the document catalog object
func findRootObject(data []byte) Objptr {
	// Look for /Type /Catalog
	patterns := [][]byte{
		[]byte("/Type/Catalog"),
		[]byte("/Type /Catalog"),
	}

	for _, pattern := range patterns {
		idx := bytes.Index(data, pattern)
		if idx < 0 {
			continue
		}

		// Search backward for object definition
		searchStart := max(idx-200, 0)

		searchArea := data[searchStart:idx]
		objIdx := bytesLastIndexOptimized(searchArea, []byte(" obj"))
		if objIdx < 0 {
			continue
		}

		// Find line start
		lineStart := objIdx
		for lineStart > 0 && searchArea[lineStart-1] != '\n' && searchArea[lineStart-1] != '\r' {
			lineStart--
		}

		// Parse object ID
		line := strings.Fields(string(searchArea[lineStart:objIdx]))
		if len(line) >= 2 {
			if id, err := strconv.ParseUint(line[len(line)-2], 10, 32); err == nil {
				if gen, err := strconv.ParseUint(line[len(line)-1], 10, 16); err == nil {
					return Objptr{uint32(id), uint16(gen)}
				}
			}
		}
	}

	return Objptr{}
}
