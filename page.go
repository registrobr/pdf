// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"fmt"
	"sort"
	"strings"
)

// A Page represent a single page in a PDF file.
// The methods interpret a Page dictionary stored in V.
type Page struct {
	Value
	*Reader
	xobjects map[string]struct{}
}

// Page returns the page for the given page number.
// Page numbers are indexed starting at 1, not 0.
// If the page is not found, Page returns a Page with p.V.IsNull().
func (r *Reader) Page(num int) Page {
	num-- // now 0-indexed
	page := r.Trailer().Key("Root").Key("Pages")
Search:
	for page.Key("Type").Name() == "Pages" {
		count := int(page.Key("Count").Int64())
		if count < num {
			return Page{}
		}
		kids := page.Key("Kids")
		for i := 0; i < kids.Len(); i++ {
			kid := kids.Index(i)
			if kid.Key("Type").Name() == "Pages" {
				c := int(kid.Key("Count").Int64())
				if num < c {
					page = kid
					continue Search
				}
				num -= c
				continue
			}
			if kid.Key("Type").Name() == "Page" {
				if num == 0 {
					return Page{
						Value:  kid,
						Reader: r,
					}
				}
				num--
			}
		}
		break
	}
	return Page{}
}

// NumPage returns the number of pages in the PDF file.
func (r *Reader) NumPage() int {
	return int(r.Trailer().Key("Root").Key("Pages").Key("Count").Int64())
}

func (p *Page) findInherited(key string) Value {
	for v := p.Value; !v.IsNull(); v = v.Key("Parent") {
		if r := v.Key(key); !r.IsNull() {
			return r
		}
	}
	return Value{}
}

/*
func (p *Page) MediaBox() Value {
	return p.findInherited("MediaBox")
}

func (p *Page) CropBox() Value {
	return p.findInherited("CropBox")
}
*/

// Resources returns the resources dictionary associated with the page.
func (p *Page) Resources() Value {
	return p.findInherited("Resources")
}

// Fonts returns a list of the fonts associated with the page.
func (p *Page) Fonts() []string {
	return p.Resources().Key("Font").Keys()
}

// Font returns the font with the given name associated with the page.
func (p *Page) Font(name string) Font {
	p.r.fontMutex.Lock()
	defer p.r.fontMutex.Unlock()

	if f, found := p.r.fontCache[name]; found {
		return f
	}
	p.logger("new font %s", name)
	v := p.Resources().Key("Font").Key(name)
	if v.IsNull() {
		xobjects := p.Resources().Key("XObject")
		for _, k := range xobjects.Keys() {
			v = xobjects.Key(k).Key("Resources").Key("Font").Key(name)
			if !v.IsNull() {
				break
			}
		}
	}
	response := Font{
		Value:  v,
		Reader: p.r,
		name:   name,
	}
	response.Encoder()
	p.r.fontCache[name] = response
	return response
}

// A Font represent a font in a PDF file.
// The methods interpret a Font dictionary stored in V.
type Font struct {
	Value
	*Reader
	name string
	enc  TextEncoding
}

var nopFont = Font{Reader: &Reader{logger: func(string, ...any) {}}}

// BaseFont returns the font's name (BaseFont property).
func (f Font) BaseFont() string {
	return f.Key("BaseFont").Name()
}

// FirstChar returns the code point of the first character in the font.
func (f Font) FirstChar() int {
	return int(f.Key("FirstChar").Int64())
}

// LastChar returns the code point of the last character in the font.
func (f Font) LastChar() int {
	return int(f.Key("LastChar").Int64())
}

// Widths returns the widths of the glyphs in the font.
// In a well-formed PDF, len(f.Widths()) == f.LastChar()+1 - f.FirstChar().
func (f Font) Widths() []float64 {
	x := f.Key("Widths")
	var out []float64
	for i := 0; i < x.Len(); i++ {
		out = append(out, x.Index(i).Float64())
	}
	return out
}

// Width returns the width of the given code point.
func (f Font) Width(code int) float64 {
	first := f.FirstChar()
	last := f.LastChar()
	if code < first || last < code {
		return 0
	}
	return f.Key("Widths").Index(code - first).Float64()
}

// Encoder returns the encoding between font code point sequences and UTF-8.
func (f *Font) Encoder() TextEncoding {
	if f == nil {
		return nil
	}

	if f.enc == nil { // caching the Encoder so we don't have to continually parse charmap
		f.enc = f.buildEncoder()
		if f.enc == nil {
			f.logger("no cmap for %s", f.name)
			f.enc = &nopEncoder{}
		}
	}
	return f.enc
}

func (f *Font) buildEncoder() TextEncoding {
	enc := f.Key("Encoding")
	switch enc.Kind() {
	case Name:
		switch enc.Name() {
		case "WinAnsiEncoding":
			return &byteEncoder{&winAnsiEncoding}
		case "MacRomanEncoding":
			return &byteEncoder{&macRomanEncoding}
		case "Identity-H":
			// ok, try ToUnicode
		default:
			f.logger("unknown encoding %s", enc.Name())
			return &nopEncoder{}
		}
	case Dict:
		return &dictEncoder{enc.Key("Differences")}
	case Null:
		// ok, try ToUnicode
	default:
		f.logger("unexpected encoding %s", enc.String())
		return &nopEncoder{}
	}

	toUnicode := f.Key("ToUnicode")
	k := toUnicode.Kind()
	if k == Dict || k == Stream {
		m := readCmap(toUnicode)
		if m == nil {
			return &nopEncoder{}
		} else if cm, ok := m.(*cmap); ok {
			cm.f = f
		}
		return m
	}

	return &byteEncoder{&pdfDocEncoding}
}

type dictEncoder struct {
	v Value
}

func (e *dictEncoder) Decode(raw string) (text string) {
	r := make([]rune, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		ch := rune(raw[i])
		n := -1
		for j := 0; j < e.v.Len(); j++ {
			x := e.v.Index(j)
			if x.Kind() == Integer {
				n = int(x.Int64())
				continue
			}
			if x.Kind() == Name {
				if int(raw[i]) == n {
					r := nameToRune[x.Name()]
					if r != 0 {
						ch = r
						break
					}
				}
				n++
			}
		}
		r = append(r, ch)
	}
	return string(r)
}

// A TextEncoding represents a mapping between
// font code points and UTF-8 text.
type TextEncoding interface {
	// Decode returns the UTF-8 text corresponding to
	// the sequence of code points in raw.
	Decode(raw string) (text string)
}

type nopEncoder struct {
}

func (e *nopEncoder) Decode(raw string) (text string) {
	return raw
}

type byteEncoder struct {
	table *[256]rune
}

func (e *byteEncoder) Decode(raw string) (text string) {
	r := make([]rune, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		r = append(r, e.table[raw[i]])
	}
	return string(r)
}

type cmap struct {
	space         [4][][2]string
	bfrangeCur    *[]bfrange
	bfrange       []bfrange
	bfrangeExt    []bfrange
	bfchar        map[int]string
	bfcharKeySize int
	f             *Font
}

func (m *cmap) Decode(raw string) (text string) {
	var r []rune

	if m.bfchar != nil {
		for i := 0; i < len(raw); i += m.bfcharKeySize {
			key := strToInt(raw[i : i+m.bfcharKeySize])
			r = append(r, []rune(m.bfchar[key])...)
		}
		return string(r)
	}

Parse:
	for len(raw) > 0 {
		for n := 1; n <= 4 && n <= len(raw); n++ { // number of digits in character replacement (1-4 possible)
			for _, space := range m.space[n-1] { // find matching codespace Ranges for number of digits
				if space[0] <= raw[:n] && raw[:n] <= space[1] { // see if value is in range
					text := raw[:n]
					raw = raw[n:]
					runes := m.find(text, n)
					if runes == nil && m.bfrangeCur == &m.bfrange {
						m.bfrangeCur = &m.bfrangeExt
						runes = m.find(text, n)
					}
					if runes == nil {
						m.f.logger("%s: no text for %X", m.f.name, text)
						r = append(r, noRune)
					} else {
						r = append(r, runes...)
					}
					continue Parse
				}
			}
		}
		m.f.logger("%s: no code space found", m.f.name)
		r = append(r, noRune)
		raw = raw[1:]
	}
	return string(r)
}

func (m *cmap) find(text string, sz int) []rune {
	bfranges := *m.bfrangeCur
	// Find first range whose hi >= text
	i := sort.Search(len(bfranges), func(i int) bool {
		bf := bfranges[i]

		// Skip smaller sizes
		if len(bf.hi) < sz {
			return false
		}

		// Larger sizes are considered >=
		if len(bf.hi) > sz {
			return true
		}

		return bf.hi >= text
	})

	if i >= len(bfranges) {
		return nil
	}

	bf := bfranges[i]

	// Validate actual match
	if len(bf.lo) != sz || bf.lo > text || text > bf.hi {
		return nil
	}

	switch bf.dst.Kind() {
	case String:
		s := bf.dst.RawString()

		if bf.lo != text {
			b := []byte(s)

			// Increment from end (supports carry)
			diff := int(text[len(text)-1]) - int(bf.lo[len(bf.lo)-1])

			for j := len(b) - 1; j >= 0 && diff > 0; j-- {
				v := int(b[j]) + diff
				b[j] = byte(v & 0xff)
				diff = v >> 8
			}

			s = string(b)
		}

		return []rune(utf16Decode(s))

	case Array:
		fmt.Printf("array %v\n", bf.dst)

	default:
		fmt.Printf("unknown dst %v\n", bf.dst)
	}

	return nil
}

type bfrange struct {
	lo  string
	hi  string
	dst Value
}

// nolint: gocyclo
func readCmap(toUnicode Value) TextEncoding {
	n := -1
	s := -1
	m := cmap{
		f: &nopFont,
	}
	m.bfrangeCur = &m.bfrange

	ok := true
	var bfranges []bfrange

	Interpret(toUnicode, func(stk *Stack, op string) {
		if !ok {
			return
		}
		switch op {
		case "findresource":
			stk.Pop()
			stk.Pop()
			//fmt.Println("findresource", key, category)
			stk.Push(newDict())
		case "begincmap":
			stk.Push(newDict())
		case "endcmap":
			stk.Pop()
		case "beginbfchar":
			s = int(stk.Pop().Int64())
		case "endbfchar":
			if s < 0 {
				println("missing beginbfchar")
				ok = false
				return
			}
			m.bfchar = make(map[int]string)
			for i := 0; i < s; i++ {
				hiStr, loStr := stk.Pop().RawString(), stk.Pop().RawString()
				if len(loStr) > 2 || len(hiStr) > 2 {
					fmt.Printf("bad char element [%d] [%d]\n", strToInt(loStr), strToInt(hiStr))
					ok = false
					return
				}
				m.bfcharKeySize = len(loStr)
				r := rune(strToInt(hiStr))
				// fmt.Printf("[%d] => [%c]\n", strToInt(loStr), r)
				m.bfchar[strToInt(loStr)] = string(r)
			}
			s = -1

		case "begincodespacerange":
			n = int(stk.Pop().Int64())
		case "endcodespacerange":
			if n < 0 {
				println("missing begincodespacerange")
				ok = false
				return
			}
			for i := 0; i < n; i++ {
				hi, lo := stk.Pop().RawString(), stk.Pop().RawString()
				if len(lo) == 0 || len(lo) != len(hi) {
					println("bad codespace range")
					ok = false
					return
				}
				m.space[len(lo)-1] = append(m.space[len(lo)-1], [2]string{lo, hi})
			}
			n = -1
		case "beginbfrange":
			n = int(stk.Pop().Int64())
		case "endbfrange":
			if n < 0 {
				panic("missing beginbfrange")
			}
			for i := 0; i < n; i++ {
				dst, srcHi, srcLo := stk.Pop(), stk.Pop().RawString(), stk.Pop().RawString()
				if dst.Kind() == Array {
					// Expand array
					l := strToInt(srcLo)
					h := strToInt(srcHi)
					if h-l+1 <= dst.Len() {
						for i := 0; i < dst.Len(); i++ {
							idx := intToStr(l + i)
							bfranges = append(bfranges, bfrange{idx, idx, dst.Index(i)})
						}
					}
					//fmt.Printf("%+v %+v\n", l, h)

				} else {
					bfranges = append(bfranges, bfrange{srcLo, srcHi, dst})
				}
			}

		case "defineresource":
			stk.Pop()
			value := stk.Pop()
			stk.Pop()
			//fmt.Println("defineresource", key, value, category)
			stk.Push(value)
		default:
			//println("interp\t", op)
		}
	})
	if !ok {
		return nil
	}

	if len(bfranges) > 0 {
		sortRanges(bfranges)
		m.bfrange = bfranges
		// for i, v := range bfranges {
		// 	fmt.Printf("%d %X %X - %s\n", i, v.lo, v.hi, v.dst)
		// }
		// fmt.Printf("============================\n")

		// build an extended charmap
		// fill gaps between two contiguous entries
		ext := []bfrange{bfranges[0]}
		for i := 1; i < len(bfranges); i++ {
			last := &ext[len(ext)-1]
			cur := bfranges[i]

			contiguous := last.lo == last.hi &&
				cur.lo == cur.hi &&
				strToInt(cur.lo)-strToInt(last.lo) == strToInt(cur.dst.RawString())-strToInt(last.dst.RawString())

			if contiguous {
				offset := 1
				for j := strToInt(last.lo) + 1; j < strToInt(cur.lo); j++ {
					idx := intToStr(j)
					v := Value{obj: Object{Kind: String, StringVal: intToStr(strToInt(last.dst.RawString()) + offset)}}
					offset++
					ext = append(ext, bfrange{idx, idx, v})
				}
			}
			ext = append(ext, cur)
		}

		// extend up to 0xff
		last := &ext[len(ext)-1]
		lastIdx := strToInt(last.lo)
		offset := 1
		for range 0xff - max(lastIdx, strToInt(last.dst.RawString())) {
			idx := intToStr(lastIdx + offset)
			v := Value{obj: Object{Kind: String, StringVal: intToStr(strToInt(last.dst.RawString()) + offset)}}
			offset++
			ext = append(ext, bfrange{idx, idx, v})
		}

		// if len(ext) != len(bfranges) {
		// 	for i, v := range ext {
		// 		fmt.Printf("%d %X %X - %s\n", i, v.lo, v.hi, v.dst)
		// 	}
		// }
		m.bfrangeExt = ext
	}
	return &m
}

func sortRanges(bfranges []bfrange) {
	sort.Slice(bfranges, func(i, j int) bool {
		if len(bfranges[i].lo) != len(bfranges[j].lo) {
			return len(bfranges[i].lo) < len(bfranges[j].lo)
		}

		if bfranges[i].lo != bfranges[j].lo {
			return bfranges[i].lo < bfranges[j].lo
		}

		return bfranges[i].hi < bfranges[j].hi
	})
}

func strToInt(s string) int {
	b := []byte(s)
	if len(b) > 1 {
		return int(b[0])<<8 | int(b[1])
	} else if len(b) > 0 {
		return int(b[0])
	}
	return 0
}

func intToStr(i int) string {
	return string([]byte{
		byte((i >> 8) & 0xff),
		byte(i & 0xff),
	})
}

type matrix [3][3]float64

var ident = matrix{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}}

func (x matrix) mul(y matrix) matrix {
	var z matrix
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			for k := 0; k < 3; k++ {
				z[i][j] += x[i][k] * y[k][j]
			}
		}
	}
	return z
}

// A Text represents a single piece of text drawn on a page.
type Text struct {
	Font     string  // the font used
	FontSize float64 // the font size, in points (1/72 of an inch)
	X        float64 // the X coordinate, in points, increasing left to right
	Y        float64 // the Y coordinate, in points, increasing bottom to top
	W        float64 // the width of the text, in points
	S        string  // the actual UTF-8 text
}

// A Rect represents a rectangle.
type Rect struct {
	Min, Max Point
}

// A Point represents an X, Y pair.
type Point struct {
	X float64
	Y float64
}

// Content describes the basic content on a page: the text and any drawn rectangles.
type Content struct {
	Text []Text
	Rect []Rect
}

type gstate struct {
	Tc    float64
	Tw    float64
	Th    float64
	Tl    float64
	Tf    Font
	Tfs   float64
	Tmode int
	Trise float64
	Tm    matrix
	Tlm   matrix
	Trm   matrix
	CTM   matrix
}

// Content returns the page's content.
func (p *Page) Content() Content {
	p.xobjects = make(map[string]struct{})
	strm := p.Key("Contents")
	response := p.contentStream(strm)

	return response
}

// It recovers from panics caused by malformed content streams and returns
// an empty Content in such cases for security and robustness.
// nolint: gocyclo
func (p *Page) contentStream(strm Value) (result Content) {
	var text []Text
	var rect []Rect

	// Security: recover from panics in malformed content streams
	defer func() {
		if r := recover(); r != nil {
			result = Content{text, rect}
		}
	}()

	// Handle in case the content page is empty
	if p.IsNull() || p.Key("Contents").Kind() == Null {
		return
	}

	var enc TextEncoding = &nopEncoder{}

	var g = gstate{
		Th:  1,
		CTM: ident,
	}

	showText := func(s string) {
		n := 0
		var part []Text
		for _, ch := range enc.Decode(s) {
			Trm := matrix{{g.Tfs * g.Th, 0, 0}, {0, g.Tfs, 0}, {0, g.Trise, 1}}.mul(g.Tm).mul(g.CTM)
			var w0 float64
			if g.Tf.FirstChar() != 0 {
				w0 = g.Tf.Width(int(s[n]))
			} else {
				w0 = 1.0
			}
			n++
			//if ch != ' ' {
			f := g.Tf.BaseFont()
			if i := strings.Index(f, "+"); i >= 0 {
				f = f[i+1:]
			}
			part = append(part, Text{f, Trm[0][0], Trm[2][0], Trm[2][1], w0 / 1000 * Trm[0][0], string(ch)})
			//}
			//p.logger("%f %f", text[len(text)-1].X, text[len(text)-1].Y)
			tx := w0/1000*g.Tfs + g.Tc
			if ch == ' ' {
				tx += g.Tw
			}
			tx *= g.Th
			g.Tm = matrix{{1, 0, 0}, {0, 1, 0}, {tx, 0, 1}}.mul(g.Tm)
		}

		/*
			hexdump(p.logger, []byte(s))
			sb := bytes.Buffer{}
			for _, p := range part {
				sb.WriteString(p.S)
			}
			hexdump(p.logger, sb.Bytes())
		*/
		text = append(text, part...)
	}

	var gstack []gstate
	Interpret(strm, func(stk *Stack, op string) {
		n := stk.Len()
		args := make([]Value, n)
		for i := n - 1; i >= 0; i-- {
			args[i] = stk.Pop()
		}
		// p.logger("   %s %+v", op, args)
		switch op {
		default:
			// p.logger("ig %s %s", op, args)
			return

		case "cm": // update g.CTM
			if len(args) != 6 {
				panic("bad g.Tm")
			}
			var m matrix
			for i := range 6 {
				m[i/2][i%2] = args[i].Float64()
			}
			m[2][2] = 1
			g.CTM = m.mul(g.CTM)

		case "gs": // set parameters from graphics state resource
		/*
			gs := p.Resources().Key("ExtGState").Key(args[0].Name())
			font := gs.Key("Font")
			if font.Kind() == Array && font.Len() == 2 {
				fmt.Println("FONT", font)
			}
		*/
		case "c": // Append curved segment to path (three control points)
		case "d": // Set line dash pattern
		case "f": // fill
		case "g": // setgray
		case "h": // Close subpath
		case "j": // Set line join style
		case "l": // lineto
		case "m": // moveto
		case "n": // End path without filling or stroking
		case "w": // Set line width

		case "J": // Set line cap style
		case "M": // Set miter limit
		case "S": // Stroke path
		case "W": // Set clipping path using non-zero winding number rule
		case "W*": // Set clipping path using non-zero winding number rule

		case "cs": // set colorspace non-stroking
		case "Do": // Invoke named XObject
			if len(args) != 1 {
				panic("bad Do")
			}
			name := strings.TrimPrefix(args[0].String(), "/")
			v := p.Key("Resources").Key("XObject").Key(name)
			if _, found := p.xobjects[name]; !found && v.Kind() == Stream && v.Key("Subtype").Name() == "Form" {
				p.xobjects[name] = struct{}{}
				item := p.contentStream(v)
				rect = append(rect, item.Rect...)
				text = append(text, item.Text...)
				delete(p.xobjects, name)
			}

		case "RG": // Set RGB colour for stroking operations
		case "rg": // Set RGB colour for nonstroking operations
		case "SCN": // (PDF 1.2) Set colour for stroking operations (ICCBased and special colour spaces)
		case "scn": // set color non-stroking

		case "re": // append rectangle to path
			if len(args) != 4 {
				panic("bad re")
			}
			x, y, w, h := args[0].Float64(), args[1].Float64(), args[2].Float64(), args[3].Float64()
			rect = append(rect, Rect{Point{x, y}, Point{x + w, y + h}})

		case "q": // save graphics state
			gstack = append(gstack, g)

		case "Q": // restore graphics state
			n := len(gstack) - 1
			if n >= 0 {
				g = gstack[n]
				gstack = gstack[:n]
			}

		case "BDC": // Begin a marked-content sequence terminated by a balancing EMC operator.
			//p.logger("   BDC %d %s %s", len(args), args[0], args[1])
		case "EMC": // End a marked-content sequence begun by a BMC or BDC operator.

		case "BT": // begin text (reset text matrix and line matrix)
			g.Tm = ident
			g.Tlm = g.Tm

		case "ET": // end text

		case "T*": // move to start of next line
			x := matrix{{1, 0, 0}, {0, 1, 0}, {0, -g.Tl, 1}}
			g.Tlm = x.mul(g.Tlm)
			g.Tm = g.Tlm

		case "Tc": // set character spacing
			if len(args) != 1 {
				panic("bad Tc")
			}
			g.Tc = args[0].Float64()

		case "TD": // move text position and set leading
			if len(args) != 2 {
				panic("bad TD")
			}
			g.Tl = -args[1].Float64()
			fallthrough

		case "Td": // move text position
			if len(args) != 2 {
				panic("bad Td")
			}
			tx := args[0].Float64()
			ty := args[1].Float64()
			x := matrix{{1, 0, 0}, {0, 1, 0}, {tx, ty, 1}}
			g.Tlm = x.mul(g.Tlm)
			g.Tm = g.Tlm

		case "Tf": // set text font and size
			if len(args) != 2 {
				panic("bad Tf")
			}
			g.Tf = p.Font(args[0].Name())
			enc = g.Tf.Encoder()
			g.Tfs = args[1].Float64()

		case "\"": // set spacing, move to next line, and show text
			if len(args) != 3 {
				panic("bad \" operator")
			}
			g.Tw = args[0].Float64()
			g.Tc = args[1].Float64()
			args = args[2:]
			fallthrough
		case "'": // move to next line and show text
			if len(args) != 1 {
				panic("bad ' operator")
			}
			x := matrix{{1, 0, 0}, {0, 1, 0}, {0, -g.Tl, 1}}
			g.Tlm = x.mul(g.Tlm)
			g.Tm = g.Tlm
			fallthrough
		case "Tj": // show text
			if len(args) != 1 || args[0].Kind() != String {
				panic("bad Tj operator")
			}
			//p.logger("  Tj:")
			//hexdump(p.logger, []byte(args[0].RawString()))
			showText(args[0].RawString())

		case "TJ": // show text, allowing individual glyph positioning
			v := args[0]
			for i := 0; i < v.Len(); i++ {
				x := v.Index(i)
				if x.Kind() == String {
					//p.logger("  TJ: %x", x.RawString())
					//hexdump(p.logger, []byte(x.RawString()))
					showText(x.RawString())
				} else {
					tx := -x.Float64() / 1000 * g.Tfs * g.Th
					g.Tm = matrix{{1, 0, 0}, {0, 1, 0}, {tx, 0, 1}}.mul(g.Tm)
				}
			}

		case "TL": // set text leading
			if len(args) != 1 {
				panic("bad TL")
			}
			g.Tl = args[0].Float64()

		case "Tm": // set text matrix and line matrix
			if len(args) != 6 {
				panic("bad Tm")
			}
			var m matrix
			for i := range 6 {
				m[i/2][i%2] = args[i].Float64()
			}
			m[2][2] = 1
			g.Tm = m
			g.Tlm = m

		case "Tr": // set text rendering mode
			if len(args) != 1 {
				panic("bad Tr")
			}
			g.Tmode = int(args[0].Int64())

		case "Ts": // set text rise
			if len(args) != 1 {
				panic("bad Ts")
			}
			g.Trise = args[0].Float64()

		case "Tw": // set word spacing
			if len(args) != 1 {
				panic("bad Tw")
			}
			g.Tw = args[0].Float64()

		case "Tz": // set horizontal text scaling
			if len(args) != 1 {
				panic("bad Tz")
			}
			g.Th = args[0].Float64() / 100
		}
	})
	return Content{text, rect}
}

// TextVertical implements sort.Interface for sorting
// a slice of Text values in vertical order, top to bottom,
// and then left to right within a line.
type TextVertical []Text

func (x TextVertical) Len() int      { return len(x) }
func (x TextVertical) Swap(i, j int) { x[i], x[j] = x[j], x[i] }
func (x TextVertical) Less(i, j int) bool {
	if x[i].Y != x[j].Y {
		return x[i].Y > x[j].Y
	}
	return x[i].X < x[j].X
}

// TextHorizontal implements sort.Interface for sorting
// a slice of Text values in horizontal order, left to right,
// and then top to bottom within a column.
type TextHorizontal []Text

func (x TextHorizontal) Len() int      { return len(x) }
func (x TextHorizontal) Swap(i, j int) { x[i], x[j] = x[j], x[i] }
func (x TextHorizontal) Less(i, j int) bool {
	if x[i].X != x[j].X {
		return x[i].X < x[j].X
	}
	return x[i].Y > x[j].Y
}

// An Outline is a tree describing the outline (also known as the table of contents)
// of a document.
type Outline struct {
	Title string    // title for this element
	Child []Outline // child elements
}

// Outline returns the document outline.
// The Outline returned is the root of the outline tree and typically has no Title itself.
// That is, the children of the returned root are the top-level entries in the outline.
func (r *Reader) Outline() Outline {
	return buildOutline(r.Trailer().Key("Root").Key("Outlines"))
}

func buildOutline(entry Value) Outline {
	var x Outline
	x.Title = entry.Key("Title").Text()
	for child := entry.Key("First"); child.Kind() == Dict; child = child.Key("Next") {
		x.Child = append(x.Child, buildOutline(child))
	}
	return x
}
