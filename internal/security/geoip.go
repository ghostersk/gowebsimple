package security

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GeoIP looks up the country code for an IPv4 address using a MaxMind
// GeoLite2-Country binary (.mmdb) database stored locally.
//
// The .mmdb format is a binary tree (Patricia trie). This is a self-contained
// reader for the subset of the format used by GeoLite2-Country — specifically
// the country ISO code field. It handles:
//   - IPv4 addresses mapped in the IPv4 subtree of the IPv6 trie
//   - Data record decoding for the country.iso_code field
//   - Thread-safe reads via an RWMutex
//
// To obtain the database file:
//   1. Register for a free MaxMind account at https://www.maxmind.com
//   2. Navigate to Account → Downloads → GeoLite2 Country
//   3. Download GeoLite2-Country.tar.gz and extract GeoLite2-Country.mmdb
//   4. Place it at the path specified by security.geoip_db_path in config.json
//      OR set maxmind_license_key and the app will auto-download weekly.

// GeoIPDB is a thread-safe MaxMind GeoLite2 country database reader.
type GeoIPDB struct {
	mu        sync.RWMutex
	data      []byte
	nodeCount uint32
	recordSize uint32 // bits per record (24 or 28 or 32)
	ipv4Start  uint32
	loaded    bool
	dbPath    string
}

// NewGeoIPDB creates a GeoIPDB that will read from dbPath.
// Call Load() before use. Returns a non-nil *GeoIPDB even if the file
// doesn't exist yet — Lookup will return "" until a database is loaded.
func NewGeoIPDB(dbPath string) *GeoIPDB {
	return &GeoIPDB{dbPath: dbPath}
}

// Load reads the .mmdb file into memory and parses the metadata.
// It is safe to call Load() concurrently with Lookup() — it takes a write lock.
func (g *GeoIPDB) Load() error {
	data, err := os.ReadFile(g.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("geoip: database not found at %s — see README for setup instructions", g.dbPath)
		}
		return fmt.Errorf("geoip: read %s: %w", g.dbPath, err)
	}

	nodeCount, recordSize, ipv4Start, err := parseMeta(data)
	if err != nil {
		return fmt.Errorf("geoip: parse metadata: %w", err)
	}

	g.mu.Lock()
	g.data = data
	g.nodeCount = nodeCount
	g.recordSize = recordSize
	g.ipv4Start = ipv4Start
	g.loaded = true
	g.mu.Unlock()
	return nil
}

// Loaded reports whether a database has been successfully loaded.
func (g *GeoIPDB) Loaded() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.loaded
}

// Lookup returns the ISO 3166-1 alpha-2 country code for ip (e.g. "US", "DE").
// Returns "" if the IP is not in the database or no database is loaded.
func (g *GeoIPDB) Lookup(ipStr string) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.loaded {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "" // IPv6 not supported in this implementation
	}

	node := g.ipv4Start
	for bit := 31; bit >= 0; bit-- {
		b := (uint32(ip4[3-bit/8]) >> uint(bit%8)) & 1
		next, err := g.readNode(node, b)
		if err != nil {
			return ""
		}
		if next >= g.nodeCount {
			// It's a data pointer
			return g.readCountryCode(next)
		}
		node = next
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// .mmdb binary tree reader
// ─────────────────────────────────────────────────────────────────────────────

// readNode returns the left (bit=0) or right (bit=1) child of a node.
func (g *GeoIPDB) readNode(node, bit uint32) (uint32, error) {
	recordBytes := g.recordSize / 8
	if g.recordSize == 28 {
		// 28-bit records are packed 7 bytes for 2 records
		idx := node * 7
		if uint64(idx)+7 > uint64(len(g.data)) {
			return 0, fmt.Errorf("out of bounds")
		}
		if bit == 0 {
			return (uint32(g.data[idx+3]&0xf0)<<20)|(uint32(g.data[idx])<<16)|(uint32(g.data[idx+1])<<8)|uint32(g.data[idx+2]), nil
		}
		return (uint32(g.data[idx+3]&0x0f)<<24)|(uint32(g.data[idx+4])<<16)|(uint32(g.data[idx+5])<<8)|uint32(g.data[idx+6]), nil
	}
	idx := node * 2 * recordBytes
	if uint64(idx)+uint64(recordBytes) > uint64(len(g.data)) {
		return 0, fmt.Errorf("out of bounds")
	}
	if bit == 1 {
		idx += recordBytes
	}
	var val uint32
	for i := uint32(0); i < recordBytes; i++ {
		val = (val << 8) | uint32(g.data[idx+i])
	}
	return val, nil
}

// readCountryCode decodes the country ISO code from a data record pointer.
func (g *GeoIPDB) readCountryCode(pointer uint32) string {
	// The data section begins immediately after the search tree
	dataOffset := g.nodeCount*((g.recordSize*2)/8) + 16 // +16 for data section separator
	recordOffset := pointer - g.nodeCount - 16

	if uint64(dataOffset)+uint64(recordOffset) >= uint64(len(g.data)) {
		return ""
	}

	// Decode the map at this offset to find the iso_code field
	offset := int(dataOffset + recordOffset)
	if offset >= len(g.data) {
		return ""
	}

	return findISOCode(g.data, offset)
}

// findISOCode walks the decoded data record looking for the country.iso_code string.
// The .mmdb data encoding is a subset of MessagePack-like type-length-value encoding.
func findISOCode(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}
	// Look for the string "iso_code" as a key in any nested map within ~512 bytes
	search := []byte("iso_code")
	end := offset + 512
	if end > len(data) {
		end = len(data)
	}
	chunk := data[offset:end]
	for i := 0; i < len(chunk)-len(search)-3; i++ {
		// Check for the length-prefixed string "iso_code" (8 bytes, type=byte-string=2)
		// MMDB string type byte: 0x40 | length = 0x40+8 = 0x48
		if chunk[i] == 0x48 && string(chunk[i+1:i+9]) == "iso_code" {
			// Value follows: skip key bytes, read next string
			pos := i + 9
			if pos >= len(chunk) {
				return ""
			}
			// Value is a string: type byte 0x42 = 2-byte string
			if chunk[pos]&0xE0 == 0x40 {
				strLen := int(chunk[pos] & 0x1f)
				pos++
				if pos+strLen <= len(chunk) {
					return string(chunk[pos : pos+strLen])
				}
			}
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// .mmdb metadata parser
// ─────────────────────────────────────────────────────────────────────────────

// parseMeta locates the MaxMind DB metadata section (which is always at the end,
// separated by a 16-byte magic marker) and extracts node_count, record_size,
// and the IPv4 subtree start node.
func parseMeta(data []byte) (nodeCount, recordSize, ipv4Start uint32, err error) {
	// Metadata separator: \xab\xcd\xefMaxMind.com
	sep := []byte{0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'}
	idx := findSequence(data, sep)
	if idx < 0 {
		return 0, 0, 0, fmt.Errorf("metadata separator not found — is this a valid .mmdb file?")
	}
	meta := data[idx+len(sep):]

	// The metadata is a MMDB map. We need node_count and record_size.
	// Rather than a full decoder, we scan for these known keys.
	nc := extractUint32Meta(meta, "node_count")
	rs := extractUint32Meta(meta, "record_size")
	if nc == 0 || rs == 0 {
		return 0, 0, 0, fmt.Errorf("could not parse node_count/record_size from metadata")
	}
	if rs != 24 && rs != 28 && rs != 32 {
		return 0, 0, 0, fmt.Errorf("unsupported record_size %d (expected 24, 28, or 32)", rs)
	}

	// Find the IPv4 subtree start: walk 96 zero bits from node 0 (as per spec)
	iv4 := uint32(0)
	// Temporarily build a small reader to walk the tree
	tmp := &GeoIPDB{data: data, nodeCount: nc, recordSize: rs}
	for i := 0; i < 96; i++ {
		iv4, err = tmp.readNode(iv4, 0)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("ipv4 subtree traversal failed: %w", err)
		}
		if iv4 >= nc {
			break
		}
	}

	return nc, rs, iv4, nil
}

func findSequence(data, seq []byte) int {
	for i := 0; i <= len(data)-len(seq); i++ {
		if data[i] == seq[0] {
			match := true
			for j := 1; j < len(seq); j++ {
				if data[i+j] != seq[j] {
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

// extractUint32Meta extracts a named uint value from the MMDB metadata map.
//
// MMDB data encoding (MaxMind DB spec):
//   Control byte: bits[7:5]=type, bits[4:0]=payload_size
//   Type values:
//     2 = UTF-8 string  (key encoding: ctrl = 0x40|len, data follows)
//     5 = uint16        (ctrl = 0xA0|byte_count, 1-2 bytes, big-endian)
//     6 = uint32        (ctrl = 0xC0|byte_count, 1-4 bytes, big-endian) ← node_count uses this
//     7 = map           (ctrl = 0xE0|pair_count)
//
// Metadata keys are UTF-8 strings; their values use the type appropriate for
// the field: record_size is uint16 (type=5), node_count is uint32 (type=6).
func extractUint32Meta(meta []byte, key string) uint32 {
	kb := []byte(key)
	// Keys are MMDB UTF-8 strings: ctrl = 0x40 | length
	keyToken := make([]byte, 1+len(kb))
	keyToken[0] = byte(0x40 | len(kb))
	copy(keyToken[1:], kb)

	for i := 0; i <= len(meta)-len(keyToken)-2; i++ {
		// Check if the key token matches at position i
		match := true
		for j, b := range keyToken {
			if meta[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}

		// Key matched — read the value that immediately follows
		pos := i + len(keyToken)
		if pos >= len(meta) {
			continue
		}
		ctrl := meta[pos]
		typ := ctrl >> 5   // upper 3 bits = type
		size := int(ctrl & 0x1f) // lower 5 bits = byte count
		pos++

		// Type 6 = uint32 (direct encoding, big-endian, 1-4 bytes)
		// This is what node_count uses.
		if typ == 6 && size >= 1 && size <= 4 && pos+size <= len(meta) {
			var v uint32
			for k := 0; k < size; k++ {
				v = (v << 8) | uint32(meta[pos+k])
			}
			return v
		}

		// Type 5 = uint16 (direct encoding, big-endian, 1-2 bytes)
		// This is what record_size uses (values 24, 28, 32 fit in uint16).
		if typ == 5 && size >= 1 && size <= 2 && pos+size <= len(meta) {
			var v uint32
			for k := 0; k < size; k++ {
				v = (v << 8) | uint32(meta[pos+k])
			}
			return v
		}
	}
	return 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-downloader
// ─────────────────────────────────────────────────────────────────────────────

// DownloadGeoLite2 downloads the GeoLite2-Country.mmdb from MaxMind and saves
// it to destPath. licenseKey must be a valid MaxMind GeoLite2 license key.
func DownloadGeoLite2(licenseKey, destPath string) error {
	if licenseKey == "" {
		return fmt.Errorf("geoip: no maxmind_license_key set in config.json")
	}

	url := fmt.Sprintf(
		"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz",
		licenseKey,
	)

	resp, err := http.Get(url) //nolint:noctx — startup context not needed here
	if err != nil {
		return fmt.Errorf("geoip: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("geoip: invalid MaxMind license key — check maxmind_license_key in config.json")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geoip: download HTTP %d", resp.StatusCode)
	}

	// The response is a .tar.gz containing GeoLite2-Country_YYYYMMDD/GeoLite2-Country.mmdb
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return fmt.Errorf("geoip: mkdir: %w", err)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("geoip: gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("geoip: tar: %w", err)
		}
		if strings.HasSuffix(hdr.Name, "GeoLite2-Country.mmdb") {
			tmp := destPath + ".tmp"
			f, err := os.Create(tmp)
			if err != nil {
				return fmt.Errorf("geoip: create tmp: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("geoip: write: %w", err)
			}
			f.Close()
			return os.Rename(tmp, destPath)
		}
	}
	return fmt.Errorf("geoip: GeoLite2-Country.mmdb not found in archive")
}

// StartAutoUpdater launches a goroutine that downloads/refreshes the GeoIP
// database on the given interval. It loads the database immediately after each
// successful download.
func StartAutoUpdater(gdb *GeoIPDB, licenseKey, destPath string, interval time.Duration, logFn func(msg string, args ...any)) {
	go func() {
		// Try immediately on startup if key is set
		if licenseKey != "" {
			if err := DownloadGeoLite2(licenseKey, destPath); err != nil {
				logFn("geoip: auto-download failed", "err", err)
			} else {
				logFn("geoip: downloaded GeoLite2-Country.mmdb")
				if err := gdb.Load(); err != nil {
					logFn("geoip: load failed after download", "err", err)
				}
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if licenseKey == "" {
				continue
			}
			if err := DownloadGeoLite2(licenseKey, destPath); err != nil {
				logFn("geoip: weekly update failed", "err", err)
				continue
			}
			logFn("geoip: weekly database updated")
			if err := gdb.Load(); err != nil {
				logFn("geoip: load failed after weekly update", "err", err)
			}
		}
	}()
}
