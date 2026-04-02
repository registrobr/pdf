package pdf

import (
	"fmt"
	"runtime"
	"strings"
)

func ExtractTextFromPage(b *strings.Builder, page Page) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = fmt.Errorf("error while parsing; details: %s", e.Error())
			} else {
				err = fmt.Errorf("error while parsing; %+v", r)
			}
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			println(string(buf))
		}
	}()
	// Initialize y co-ordinate for the page
	y := 0.0

	// x co-ordinate from the last letter in the line
	x := 0.0

	// x co-ordinate (horizontal) space between 2 consecutive letters
	twoLetterDelta := 0.0

	widthDefined := false
	content := page.Content()
	for _, t := range content.Text {
		if t.W > 0 {
			widthDefined = true
			break
		}
	}
	for _, t := range content.Text {
		// Check if we are on a new line
		if t.Y != y {
			y = t.Y
			x = 0.0
			b.WriteString("\n")
		}

		if t.W > 0.0 || !widthDefined {
			if twoLetterDelta > 0 && t.X-x > ((twoLetterDelta+t.W)*4) {
				//fmt.Printf(">>>%s %f %f %f %f %f\n", t.S, t.Y, t.X, twoLetterDelta, t.X-x, (twoLetterDelta+t.W)*4)
				x = 0.0
				b.WriteString(" ")
			}
			if x > 0 && twoLetterDelta < t.X-x {
				twoLetterDelta = t.X - x
			}
			x = t.X
			//fmt.Printf("%s %f %f %f\n", t.S, t.Y, t.X, twoLetterDelta)
			b.WriteString(t.S)
		}
	}
	return nil
}

func parseMetaInfoKernel(level int, path string, value Value, response map[string]string) {
	if level > 3 {
		return
	}
	if len(value.Keys()) > 0 {
		for _, v := range value.Keys() {
			var p string
			if path == "" {
				p = v
			} else {
				p += path + "." + v
			}
			parseMetaInfoKernel(level+1, p, value.Key(v), response)
		}
	} else {
		response[path] = value.String()
	}
}

func ParseMetaInfo(value Value) map[string]string {
	response := make(map[string]string)
	parseMetaInfoKernel(0, "", value, response)
	return response
}
