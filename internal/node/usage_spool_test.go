package node

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func sampleUsageSpool() usageBufferSpool {
	return usageBufferSpool{
		NextBatch: 42,
		Pending: map[string]xray.OutboundStat{
			"direct":          {Tag: "direct", Up: 10, Down: 20},
			"tag with\x00nul": {Tag: "tag with\x00nul", Up: -1, Down: 1 << 40},
		},
		Inbounds:               map[string]xray.InboundStat{"vless-ü": {Tag: "vless-ü", Up: 7, Down: 0}},
		Users:                  map[string]int64{"12": 5, "13\x00dmVzcw": 9, "14\x00dmVzcw\x00extra": -3, "15\x00": 0},
		ActiveOutboundBatch:    "41",
		ActiveOutboundSnapshot: map[string]xray.OutboundStat{},
		ActiveInboundSnapshot:  nil,
		ActiveUserBatch:        "40",
		ActiveUserSnapshot:     map[string]int64{"12": 5},
	}
}

func TestUsageSpoolBinaryRoundTripKeepsNilAndEmptySnapshots(t *testing.T) {
	want := sampleUsageSpool()
	encoded := encodeUsageSpool(want, nil)
	if !strings.HasPrefix(string(encoded), usageSpoolMagic) {
		t.Fatalf("encoded spool does not start with the magic header")
	}
	got, err := decodeUsageSpool(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed the spool\n got: %+v\nwant: %+v", got, want)
	}
}

func TestUsageSpoolLoadsLegacyJSONAndRewritesBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage-spool.json")
	legacy := sampleUsageSpool()
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	buffer, err := newPersistentUsageBuffer(path)
	if err != nil {
		t.Fatalf("load legacy spool: %v", err)
	}
	if buffer.nextBatch != legacy.NextBatch || !reflect.DeepEqual(buffer.users, legacy.Users) {
		t.Fatalf("legacy spool was not restored: next=%d users=%v", buffer.nextBatch, buffer.users)
	}

	buffer.add([]xray.OutboundStat{{Tag: "direct", Up: 1}})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), usageSpoolMagic) {
		t.Fatalf("persist did not rewrite the spool in the binary format")
	}

	reloaded, err := newPersistentUsageBuffer(path)
	if err != nil {
		t.Fatalf("reload rewritten spool: %v", err)
	}
	if reloaded.pending["direct"].Up != legacy.Pending["direct"].Up+1 {
		t.Fatalf("pending direct up = %d, want %d", reloaded.pending["direct"].Up, legacy.Pending["direct"].Up+1)
	}
	if !reflect.DeepEqual(reloaded.activeUserSnapshot, legacy.ActiveUserSnapshot) {
		t.Fatalf("active user snapshot changed: %v", reloaded.activeUserSnapshot)
	}
}

func TestUsageSpoolRejectsDamagedFiles(t *testing.T) {
	encoded := encodeUsageSpool(sampleUsageSpool(), nil)
	flipped := append([]byte(nil), encoded...)
	flipped[len(flipped)/2] ^= 0x40
	body := []byte{0}
	body = binary.AppendUvarint(body, 1<<60)
	hostile := append([]byte(usageSpoolMagic), body...)
	hostile = binary.LittleEndian.AppendUint32(hostile, crc32.Checksum(body, usageSpoolChecksum))

	cases := map[string][]byte{
		"flipped byte":               flipped,
		"truncated":                  encoded[:len(encoded)-3],
		"trailing byte":              append(append([]byte(nil), encoded...), 0x00),
		"unknown header":             append([]byte("RBSPOOL9"), encoded[len(usageSpoolMagic):]...),
		"oversized count, valid crc": hostile,
		"empty file, magic only":     []byte(usageSpoolMagic),
	}
	for name, data := range cases {
		if _, err := decodeUsageSpool(data); err == nil {
			t.Fatalf("%s: decode accepted a damaged spool", name)
		}
	}
}

func randomSpoolString(rng *rand.Rand) string {
	alphabet := []string{"a", "7", "-", "é", "\x00", "☃", " ", "tag", "vless"}
	length := rng.IntN(6)
	var builder strings.Builder
	for i := 0; i < length; i++ {
		builder.WriteString(alphabet[rng.IntN(len(alphabet))])
	}
	return builder.String()
}

func TestUsageSpoolRandomRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for iteration := 0; iteration < 300; iteration++ {
		state := usageBufferSpool{
			NextBatch: rng.Uint64(),
			Pending:   map[string]xray.OutboundStat{},
			Inbounds:  map[string]xray.InboundStat{},
			Users:     map[string]int64{},
		}
		for i := rng.IntN(20); i > 0; i-- {
			tag := randomSpoolString(rng)
			state.Pending[tag] = xray.OutboundStat{Tag: tag, Up: rng.Int64() - rng.Int64(), Down: rng.Int64N(1 << 40)}
			state.Inbounds[tag] = xray.InboundStat{Tag: tag, Up: rng.Int64N(1000), Down: rng.Int64() - rng.Int64()}
		}
		for i := rng.IntN(200); i > 0; i-- {
			state.Users[randomSpoolString(rng)+"\x00"+randomSpoolString(rng)] = rng.Int64() - rng.Int64()
		}
		if rng.IntN(2) == 0 {
			state.ActiveUserBatch = randomSpoolString(rng)
			state.ActiveUserSnapshot = map[string]int64{randomSpoolString(rng): rng.Int64N(99)}
		}
		if rng.IntN(2) == 0 {
			state.ActiveOutboundBatch = randomSpoolString(rng)
			state.ActiveOutboundSnapshot = map[string]xray.OutboundStat{}
		}

		got, err := decodeUsageSpool(encodeUsageSpool(state, nil))
		if err != nil {
			t.Fatalf("iteration %d: decode failed: %v", iteration, err)
		}
		if !reflect.DeepEqual(got, state) {
			t.Fatalf("iteration %d: round trip changed the spool", iteration)
		}
	}
}
