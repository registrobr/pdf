package pdf

import (
	"io"
	"strings"
	"testing"
)

func TestAlphaReader(t *testing.T) {
	// Test ASCII85 character filtering (not full decoding)
	input := "87cURD]i,\"Ebo80~>"
	expected := "87cURD]i,\"Ebo80" // Filtered to valid ASCII85 chars, stops at ~>

	reader := newAlphaReader(strings.NewReader(input))
	buf := make([]byte, len(input))
	n, err := reader.Read(buf)

	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	result := string(buf[:n])
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestCheckASCII85(t *testing.T) {
	tests := []struct {
		input    byte
		expected byte
	}{
		{'!', '!'}, // 33
		{'u', 'u'}, // 117
		{'v', 0},   // 118, invalid
		{' ', 0},   // space, invalid
		{'~', 1},   // tilde marker
		{'>', '>'}, // greater than
	}

	for _, tt := range tests {
		result := checkASCII85(tt.input)
		if result != tt.expected {
			t.Errorf("checkASCII85(%q) = %d, expected %d", tt.input, result, tt.expected)
		}
	}
}

func TestAlphaReaderEOF(t *testing.T) {
	reader := newAlphaReader(strings.NewReader(""))
	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	if err != io.EOF {
		t.Errorf("Expected EOF, got %v", err)
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

func TestAlphaReaderInvalidData(t *testing.T) {
	// Test with invalid ASCII85 data
	input := "invalid~>"
	reader := newAlphaReader(strings.NewReader(input))
	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	// Should handle gracefully
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	// Should skip invalid characters
	if n == 0 {
		t.Error("Expected to read some data")
	}
}
