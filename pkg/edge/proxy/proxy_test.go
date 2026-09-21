package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestPROXYv2HeaderEncodeDecodeIPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.195"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}

	header, err := BuildPROXYv2Header(src, dst)
	if err != nil {
		t.Fatalf("failed to build PROXYv2 header: %v", err)
	}

	buf := bytes.NewReader(header)
	parsedSrc, parsedDst, err := ParsePROXYv2Header(buf)
	if err != nil {
		t.Fatalf("failed to parse PROXYv2 header: %v", err)
	}

	if !parsedSrc.IP.Equal(src.IP) || parsedSrc.Port != src.Port {
		t.Fatalf("src mismatch: expected %v, got %v", src, parsedSrc)
	}
	if !parsedDst.IP.Equal(dst.IP) || parsedDst.Port != dst.Port {
		t.Fatalf("dst mismatch: expected %v, got %v", dst, parsedDst)
	}
}

func TestPROXYv2HeaderEncodeDecodeIPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 49152}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}

	header, err := BuildPROXYv2Header(src, dst)
	if err != nil {
		t.Fatalf("failed to build PROXYv2 header IPv6: %v", err)
	}

	buf := bytes.NewReader(header)
	parsedSrc, parsedDst, err := ParsePROXYv2Header(buf)
	if err != nil {
		t.Fatalf("failed to parse PROXYv2 header IPv6: %v", err)
	}

	if !parsedSrc.IP.Equal(src.IP) || parsedSrc.Port != src.Port {
		t.Fatalf("src mismatch: expected %v, got %v", src, parsedSrc)
	}
	if !parsedDst.IP.Equal(dst.IP) || parsedDst.Port != dst.Port {
		t.Fatalf("dst mismatch: expected %v, got %v", dst, parsedDst)
	}
}
