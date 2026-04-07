package main

import (
	"flag"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	pdf "github.com/registrobr/pdf"
)

var rePunct = regexp.MustCompile(`[ ]([\]\(\\)[\{\}\,\.\:\;\!\?])`)
var reWhitespace = regexp.MustCompile(`[ \r\n\t]+`)

func extractTextFromPDF(filename string) (response string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = fmt.Errorf("error while processing %s; details: %s", filename, e)
			} else {
				err = fmt.Errorf("error while processing %s %+v", filename, r)
			}
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			println(buf)
		}
	}()

	reader, err := pdf.Open(filename)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	m := pdf.ParseMetaInfo(reader.Trailer())
	fmt.Println(filename, "Producer:", m["Info.Producer"])

	var b strings.Builder

	for i := 1; i <= reader.NumPage(); i++ {
		err = pdf.ExtractTextFromPage(&b, reader.Page(i))
		if err != nil {
			fmt.Printf("%s\n", err.Error())
		}
	}

	response = reWhitespace.ReplaceAllString(b.String(), " ")
	response = rePunct.ReplaceAllString(response, "$1")
	begin := strings.Index(response, "Destinatário")
	if begin >= 0 {
		response = response[begin:]
	}
	end := strings.Index(response, "Assinatura:")
	if end >= 0 {
		response = response[:end]
	}

	return strings.TrimSpace(response), nil
}

func main() {
	flag.Parse()
	for _, filename := range flag.Args() {
		s, err := extractTextFromPDF(filename)
		fmt.Printf("%s:\n", filename)
		if err != nil {
			fmt.Printf("error %s\n\n", err.Error())
		} else {
			fmt.Printf("%s\n\n", s)
		}
	}
}
