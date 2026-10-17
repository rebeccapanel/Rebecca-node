package node

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"strings"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

const usageSpoolMagic = "RBSPOOL1"

var (
	usageSpoolChecksum      = crc32.MakeTable(crc32.Castagnoli)
	errUsageSpoolCorrupt    = errors.New("usage spool is corrupt")
	errUsageSpoolUnknownFmt = errors.New("usage spool has an unknown format")
)

func encodeUsageSpool(state usageBufferSpool, buf []byte) []byte {
	buf = append(buf[:0], usageSpoolMagic...)
	bodyStart := len(buf)
	buf = binary.AppendUvarint(buf, state.NextBatch)
	buf = appendOutboundStats(buf, state.Pending)
	buf = appendInboundStats(buf, state.Inbounds)
	buf = appendUserCounters(buf, state.Users)
	buf = appendString(buf, state.ActiveOutboundBatch)
	buf = appendOptional(buf, state.ActiveOutboundSnapshot == nil, func(buf []byte) []byte {
		return appendOutboundStats(buf, state.ActiveOutboundSnapshot)
	})
	buf = appendOptional(buf, state.ActiveInboundSnapshot == nil, func(buf []byte) []byte {
		return appendInboundStats(buf, state.ActiveInboundSnapshot)
	})
	buf = appendString(buf, state.ActiveUserBatch)
	buf = appendOptional(buf, state.ActiveUserSnapshot == nil, func(buf []byte) []byte {
		return appendUserCounters(buf, state.ActiveUserSnapshot)
	})
	return binary.LittleEndian.AppendUint32(buf, crc32.Checksum(buf[bodyStart:], usageSpoolChecksum))
}

func decodeUsageSpool(data []byte) (usageBufferSpool, error) {
	var state usageBufferSpool
	if trimmed := bytes.TrimLeft(data, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '{' {
		err := json.Unmarshal(data, &state)
		return state, err
	}
	if len(data) < len(usageSpoolMagic)+4 || string(data[:len(usageSpoolMagic)]) != usageSpoolMagic {
		return state, errUsageSpoolUnknownFmt
	}
	body := data[len(usageSpoolMagic) : len(data)-4]
	if crc32.Checksum(body, usageSpoolChecksum) != binary.LittleEndian.Uint32(data[len(data)-4:]) {
		return state, errUsageSpoolCorrupt
	}
	reader := spoolReader{data: body}
	state.NextBatch = reader.uvarint()
	state.Pending = reader.outboundStats()
	state.Inbounds = reader.inboundStats()
	state.Users = reader.userCounters()
	state.ActiveOutboundBatch = reader.str()
	if reader.optional() {
		state.ActiveOutboundSnapshot = reader.outboundStats()
	}
	if reader.optional() {
		state.ActiveInboundSnapshot = reader.inboundStats()
	}
	state.ActiveUserBatch = reader.str()
	if reader.optional() {
		state.ActiveUserSnapshot = reader.userCounters()
	}
	if reader.err == nil && len(reader.data) != 0 {
		reader.err = errUsageSpoolCorrupt
	}
	if reader.err != nil {
		return usageBufferSpool{}, reader.err
	}
	return state, nil
}

func appendString(buf []byte, value string) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func appendOptional(buf []byte, isNil bool, appendValue func([]byte) []byte) []byte {
	if isNil {
		return append(buf, 0)
	}
	return appendValue(append(buf, 1))
}

func appendOutboundStats(buf []byte, stats map[string]xray.OutboundStat) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(stats)))
	for key, item := range stats {
		buf = appendString(buf, key)
		buf = appendString(buf, item.Tag)
		buf = binary.AppendVarint(buf, item.Up)
		buf = binary.AppendVarint(buf, item.Down)
	}
	return buf
}

func appendInboundStats(buf []byte, stats map[string]xray.InboundStat) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(stats)))
	for key, item := range stats {
		buf = appendString(buf, key)
		buf = appendString(buf, item.Tag)
		buf = binary.AppendVarint(buf, item.Up)
		buf = binary.AppendVarint(buf, item.Down)
	}
	return buf
}

func appendUserCounters(buf []byte, counters map[string]int64) []byte {
	tailIndex := map[string]uint64{}
	var tails []string
	for key := range counters {
		if _, tail, found := strings.Cut(key, "\x00"); found {
			if _, known := tailIndex[tail]; !known {
				tails = append(tails, tail)
				tailIndex[tail] = uint64(len(tails))
			}
		}
	}
	buf = binary.AppendUvarint(buf, uint64(len(tails)))
	for _, tail := range tails {
		buf = appendString(buf, tail)
	}
	buf = binary.AppendUvarint(buf, uint64(len(counters)))
	for key, value := range counters {
		uid, tail, found := strings.Cut(key, "\x00")
		buf = appendString(buf, uid)
		if found {
			buf = binary.AppendUvarint(buf, tailIndex[tail])
		} else {
			buf = binary.AppendUvarint(buf, 0)
		}
		buf = binary.AppendVarint(buf, value)
	}
	return buf
}

type spoolReader struct {
	data []byte
	err  error
}

func (r *spoolReader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	value, n := binary.Uvarint(r.data)
	if n <= 0 {
		r.err = errUsageSpoolCorrupt
		return 0
	}
	r.data = r.data[n:]
	return value
}

func (r *spoolReader) varint() int64 {
	if r.err != nil {
		return 0
	}
	value, n := binary.Varint(r.data)
	if n <= 0 {
		r.err = errUsageSpoolCorrupt
		return 0
	}
	r.data = r.data[n:]
	return value
}

func (r *spoolReader) count() int {
	value := r.uvarint()
	if r.err == nil && value > uint64(len(r.data)) {
		r.err = errUsageSpoolCorrupt
		return 0
	}
	return int(value)
}

func (r *spoolReader) str() string {
	length := r.uvarint()
	if r.err != nil {
		return ""
	}
	if length > uint64(len(r.data)) {
		r.err = errUsageSpoolCorrupt
		return ""
	}
	value := string(r.data[:length])
	r.data = r.data[length:]
	return value
}

func (r *spoolReader) optional() bool {
	if r.err != nil || len(r.data) == 0 {
		r.err = errUsageSpoolCorrupt
		return false
	}
	flag := r.data[0]
	r.data = r.data[1:]
	if flag > 1 {
		r.err = errUsageSpoolCorrupt
	}
	return flag == 1
}

func (r *spoolReader) outboundStats() map[string]xray.OutboundStat {
	n := r.count()
	result := make(map[string]xray.OutboundStat, n)
	for i := 0; i < n && r.err == nil; i++ {
		key := r.str()
		item := xray.OutboundStat{Tag: r.str()}
		item.Up = r.varint()
		item.Down = r.varint()
		result[key] = item
	}
	return result
}

func (r *spoolReader) inboundStats() map[string]xray.InboundStat {
	n := r.count()
	result := make(map[string]xray.InboundStat, n)
	for i := 0; i < n && r.err == nil; i++ {
		key := r.str()
		item := xray.InboundStat{Tag: r.str()}
		item.Up = r.varint()
		item.Down = r.varint()
		result[key] = item
	}
	return result
}

func (r *spoolReader) userCounters() map[string]int64 {
	tails := make([]string, r.count())
	for i := range tails {
		tails[i] = r.str()
	}
	n := r.count()
	result := make(map[string]int64, n)
	for i := 0; i < n && r.err == nil; i++ {
		key := r.str()
		index := r.uvarint()
		if index > uint64(len(tails)) {
			r.err = errUsageSpoolCorrupt
			break
		}
		if index > 0 {
			key += "\x00" + tails[index-1]
		}
		result[key] = r.varint()
	}
	return result
}
