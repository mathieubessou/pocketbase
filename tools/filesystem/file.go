package filesystem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/pocketbase/pocketbase/tools/inflector"
	"github.com/pocketbase/pocketbase/tools/security"
)

// FileReader defines an interface for a file resource reader.
type FileReader interface {
	Open() (io.ReadSeekCloser, error)
}

// File defines a single file [io.ReadSeekCloser] resource.
//
// The file could be from a local path, multipart/form-data header, etc.
type File struct {
	Reader       FileReader `form:"-" json:"-" xml:"-"`
	Name         string     `form:"name" json:"name" xml:"name"`
	OriginalName string     `form:"originalName" json:"originalName" xml:"originalName"`
	Size         int64      `form:"size" json:"size" xml:"size"`
}

// AsMap implements [core.mapExtractor] and returns a value suitable
// to be used in an API rule expression.
func (f *File) AsMap() map[string]any {
	return map[string]any{
		"name":         f.Name,
		"originalName": f.OriginalName,
		"size":         f.Size,
	}
}

// NewFileFromPath creates a new File instance from the provided local file path.
func NewFileFromPath(path string) (*File, error) {
	f := &File{}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	f.Reader = &PathReader{Path: path}
	f.Size = info.Size()
	f.OriginalName = info.Name()
	f.Name = normalizeName(f.Reader, f.OriginalName)

	return f, nil
}

// NewFileFromBytes creates a new File instance from the provided byte slice.
func NewFileFromBytes(b []byte, name string) (*File, error) {
	size := len(b)
	if size == 0 {
		return nil, errors.New("cannot create an empty file")
	}

	f := &File{}

	f.Reader = &BytesReader{b}
	f.Size = int64(size)
	f.OriginalName = name
	f.Name = normalizeName(f.Reader, f.OriginalName)

	return f, nil
}

// NewFileFromMultipart creates a new File from the provided multipart header.
func NewFileFromMultipart(mh *multipart.FileHeader) (*File, error) {
	f := &File{}

	f.Reader = &MultipartReader{Header: mh}
	f.Size = mh.Size
	f.OriginalName = mh.Filename
	f.Name = normalizeName(f.Reader, f.OriginalName)

	return f, nil
}

// privateIPNets contains the IP networks considered private or otherwise
// non-routable that should not be reachable via NewFileFromURL to prevent
// Server-Side Request Forgery (SSRF) attacks.
var privateIPNets []*net.IPNet

func init() {
	// loopback, link-local, private, and other special-use ranges
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918 private
		"172.16.0.0/12",  // RFC1918 private
		"192.168.0.0/16", // RFC1918 private
		"169.254.0.0/16", // IPv4 link-local
		"100.64.0.0/10",  // RFC6598 shared address space
		"192.0.0.0/24",   // RFC6890 IETF protocol assignments
		"198.18.0.0/15",  // RFC2544 benchmarking
		"198.51.100.0/24", // RFC5737 documentation
		"203.0.113.0/24", // RFC5737 documentation
		"224.0.0.0/4",    // IPv4 multicast
		"240.0.0.0/4",    // IPv4 reserved
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
		"ff00::/8",       // IPv6 multicast
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPNets = append(privateIPNets, network)
		}
	}
}

// isPrivateIP reports whether ip is a private, loopback, or otherwise
// non-routable IP address that must not be reached when fetching external URLs.
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateIPNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// safeURLHTTPClient is an HTTP client whose transport resolves each request
// host to IP addresses and blocks any that fall within private/loopback ranges
// to prevent SSRF attacks.
var safeURLHTTPClient = &http.Client{
	Transport: &ssrfSafeTransport{wrapped: http.DefaultTransport},
}

type ssrfSafeTransport struct {
	wrapped http.RoundTripper
}

func (t *ssrfSafeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()

	// Resolve the host to its IP addresses and reject private/loopback ones.
	addrs, err := net.DefaultResolver.LookupHost(req.Context(), host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("requests to private/loopback addresses are not allowed (%s)", addr)
		}
	}

	return t.wrapped.RoundTrip(req)
}

// NewFileFromURL creates a new File from the provided url by
// downloading the resource and load it as BytesReader.
//
// Only http and https URL schemes are accepted. Requests to private,
// loopback, or link-local addresses are rejected to prevent SSRF attacks.
//
// Example
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	file, err := filesystem.NewFileFromURL(ctx, "https://example.com/image.png")
func NewFileFromURL(ctx context.Context, rawURL string) (*File, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	// Allow only http and https to prevent accidental access to local
	// resources via file://, gopher://, etc.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("only http and https url schemes are supported")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}

	res, err := safeURLHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 399 {
		return nil, fmt.Errorf("failed to download url %s (%d)", rawURL, res.StatusCode)
	}

	var buf bytes.Buffer

	if _, err = io.Copy(&buf, res.Body); err != nil {
		return nil, err
	}

	return NewFileFromBytes(buf.Bytes(), path.Base(rawURL))
}

// -------------------------------------------------------------------

var _ FileReader = (*MultipartReader)(nil)

// MultipartReader defines a FileReader from [multipart.FileHeader].
type MultipartReader struct {
	Header *multipart.FileHeader
}

// Open implements the [filesystem.FileReader] interface.
func (r *MultipartReader) Open() (io.ReadSeekCloser, error) {
	return r.Header.Open()
}

// -------------------------------------------------------------------

var _ FileReader = (*PathReader)(nil)

// PathReader defines a FileReader from a local file path.
type PathReader struct {
	Path string
}

// Open implements the [filesystem.FileReader] interface.
func (r *PathReader) Open() (io.ReadSeekCloser, error) {
	return os.Open(r.Path)
}

// -------------------------------------------------------------------

var _ FileReader = (*BytesReader)(nil)

// BytesReader defines a FileReader from bytes content.
type BytesReader struct {
	Bytes []byte
}

// Open implements the [filesystem.FileReader] interface.
func (r *BytesReader) Open() (io.ReadSeekCloser, error) {
	return &bytesReadSeekCloser{bytes.NewReader(r.Bytes)}, nil
}

type bytesReadSeekCloser struct {
	*bytes.Reader
}

// Close implements the [io.ReadSeekCloser] interface.
func (r *bytesReadSeekCloser) Close() error {
	return nil
}

// -------------------------------------------------------------------

var _ FileReader = (openFuncAsReader)(nil)

// openFuncAsReader defines a FileReader from a bare Open function.
type openFuncAsReader func() (io.ReadSeekCloser, error)

// Open implements the [filesystem.FileReader] interface.
func (r openFuncAsReader) Open() (io.ReadSeekCloser, error) {
	return r()
}

// -------------------------------------------------------------------

var extInvalidCharsRegex = regexp.MustCompile(`[^\w\.\*\-\+\=\#]+`)

const randomAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func normalizeName(fr FileReader, name string) string {
	// cut the name even if it is not multibyte safe to avoid operating on too large strings
	// ---
	originalLength := len(name)
	if originalLength > 300 {
		name = name[originalLength-300:]
	}

	// extension
	// ---
	originalExt := extractExtension(name)
	cleanExt := "." + strings.Trim(extInvalidCharsRegex.ReplaceAllString(originalExt, ""), ".")
	if cleanExt == "." {
		// try to detect the extension from the file content
		cleanExt, _ = detectExtension(fr)
	}
	if extLength := len(cleanExt); extLength > 20 {
		// keep only the last 20 characters (it is multibyte safe after the regex replace)
		cleanExt = "." + strings.Trim(cleanExt[extLength-20:], ".")
	}

	// name
	//
	// note: leading dot is trimmed to prevent various subtle issues with files
	// sync programs as they sometimes have special handling for "invisible" files
	// ---
	cleanName := inflector.Snakecase(strings.Trim(strings.TrimSuffix(name, originalExt), "."))
	if length := len(cleanName); length < 3 {
		// the name is too short so we concatenate an additional random part
		cleanName += security.RandomStringWithAlphabet(10, randomAlphabet)
	} else if length > 100 {
		// keep only the first 100 characters (it is multibyte safe after Snakecase)
		cleanName = cleanName[:100]
	}

	return fmt.Sprintf(
		"%s_%s%s",
		cleanName,
		security.RandomStringWithAlphabet(10, randomAlphabet), // ensure that there is always a random part
		cleanExt,
	)
}

// extractExtension extracts the extension (with leading dot) from name.
//
// This differ from filepath.Ext() by supporting double extensions (eg. ".tar.gz").
//
// Returns an empty string if no match is found.
//
// Example:
// extractExtension("test.txt")      // .txt
// extractExtension("test.tar.gz")   // .tar.gz
// extractExtension("test.a.tar.gz") // .tar.gz
func extractExtension(name string) string {
	primaryDot := strings.LastIndex(name, ".")

	if primaryDot == -1 {
		return ""
	}

	// look for secondary extension
	secondaryDot := strings.LastIndex(name[:primaryDot], ".")
	if secondaryDot >= 0 {
		return name[secondaryDot:]
	}

	return name[primaryDot:]
}

// detectExtension tries to detect the extension from file mime type.
func detectExtension(fr FileReader) (string, error) {
	r, err := fr.Open()
	if err != nil {
		return "", err
	}
	defer r.Close()

	mt, err := mimetype.DetectReader(r)
	if err != nil {
		return "", err
	}

	return mt.Extension(), nil
}
