package node

import (
	"fmt"
	"path/filepath"

	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"golang.org/x/sys/unix"
)

func diskDiagnostics(path string) []*nodev1.ProtocolStatus {
	if path == "" {
		return nil
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(filepath.Clean(path), &stat); err != nil {
		return []*nodev1.ProtocolStatus{{Protocol: "disk", State: "warning", Detail: "Cannot inspect node data filesystem: " + err.Error()}}
	}
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	noInodes := stat.Files > 0 && stat.Ffree == 0
	if !noInodes && (total == 0 || free >= 256<<20 || free > total/20) {
		return nil
	}
	state := "warning"
	if free == 0 || (stat.Files > 0 && stat.Ffree == 0) {
		state = "error"
	}
	return []*nodev1.ProtocolStatus{{Protocol: "disk", State: state, Detail: fmt.Sprintf("Node data filesystem has only %d MiB available and %d/%d free inodes; configuration or usage-spool writes may fail", free/(1<<20), stat.Ffree, stat.Files)}}
}
