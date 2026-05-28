package xray

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type OutboundStat struct {
	Tag  string `json:"tag"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type UserStat struct {
	UID   string `json:"uid"`
	Value int64  `json:"value"`
}

func QueryOutboundStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]OutboundStat, error) {
	stats, err := queryStats(apiHost, apiPort, timeout, "outbound>>>", reset)
	if err != nil {
		return nil, err
	}

	byTag := map[string]*OutboundStat{}
	for _, stat := range stats {
		if stat == nil || stat.GetValue() == 0 {
			continue
		}
		tag, link, ok := parseOutboundStatName(stat.GetName())
		if !ok || strings.EqualFold(tag, "api") {
			continue
		}
		item := byTag[tag]
		if item == nil {
			item = &OutboundStat{Tag: tag}
			byTag[tag] = item
		}
		switch link {
		case "uplink":
			item.Up += stat.GetValue()
		case "downlink":
			item.Down += stat.GetValue()
		}
	}

	tags := make([]string, 0, len(byTag))
	for tag := range byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	result := make([]OutboundStat, 0, len(tags))
	for _, tag := range tags {
		item := byTag[tag]
		if item.Up != 0 || item.Down != 0 {
			result = append(result, *item)
		}
	}
	return result, nil
}

func QueryUserStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]UserStat, error) {
	stats, err := queryStats(apiHost, apiPort, timeout, "user>>>", reset)
	if err != nil {
		return nil, err
	}

	byUID := map[string]int64{}
	for _, stat := range stats {
		if stat == nil || stat.GetValue() == 0 {
			continue
		}
		uid, ok := parseUserStatName(stat.GetName())
		if !ok {
			continue
		}
		byUID[uid] += stat.GetValue()
	}

	uids := make([]string, 0, len(byUID))
	for uid := range byUID {
		uids = append(uids, uid)
	}
	sort.Strings(uids)

	result := make([]UserStat, 0, len(uids))
	for _, uid := range uids {
		value := byUID[uid]
		if value != 0 {
			result = append(result, UserStat{UID: uid, Value: value})
		}
	}
	return result, nil
}

func queryStats(apiHost string, apiPort int, timeout time.Duration, pattern string, reset bool) ([]*statscommand.Stat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialAPI(ctx, apiHost, apiPort)
	if err != nil {
		return nil, fmt.Errorf("connect to Xray stats API: %w", err)
	}
	defer conn.Close()

	client := statscommand.NewStatsServiceClient(conn)
	res, err := client.QueryStats(ctx, &statscommand.QueryStatsRequest{
		Pattern: pattern,
		Reset_:  reset,
	})
	if err != nil {
		return nil, fmt.Errorf("query Xray stats: %w", err)
	}
	return res.GetStat(), nil
}

func dialAPI(ctx context.Context, apiHost string, apiPort int) (*grpc.ClientConn, error) {
	host := strings.TrimSpace(apiHost)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, strconv.Itoa(apiPort))

	return grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

func parseOutboundStatName(name string) (string, string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 || parts[0] != "outbound" || parts[2] != "traffic" {
		return "", "", false
	}
	tag := strings.TrimSpace(parts[1])
	link := strings.ToLower(strings.TrimSpace(parts[3]))
	if tag == "" || (link != "uplink" && link != "downlink") {
		return "", "", false
	}
	return tag, link, true
}

func parseUserStatName(name string) (string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", false
	}
	email := strings.TrimSpace(parts[1])
	if email == "" {
		return "", false
	}
	uid, _, _ := strings.Cut(email, ".")
	uid = strings.TrimSpace(uid)
	return uid, uid != ""
}
