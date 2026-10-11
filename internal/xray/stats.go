package xray

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type OutboundStat struct {
	Tag  string `json:"tag"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type InboundStat struct {
	Tag  string `json:"tag"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type UserStat struct {
	UID        string `json:"uid"`
	Value      int64  `json:"value"`
	Up         int64  `json:"up,omitempty"`
	Down       int64  `json:"down,omitempty"`
	InboundTag string `json:"inbound_tag,omitempty"`
}

const inboundRuntimeEmailMarker = "rb1_"

type OnlineIP struct {
	IP           string `json:"ip"`
	LastSeenUnix int64  `json:"last_seen_unix"`
}

type OnlineUserIP struct {
	UID   string     `json:"uid"`
	Email string     `json:"email"`
	IPs   []OnlineIP `json:"ips"`
}

func QueryOutboundStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]OutboundStat, error) {
	stats, err := queryStats(apiHost, apiPort, timeout, "outbound>>>", reset)
	if err != nil {
		return nil, err
	}

	byTag := map[string]*OutboundStat{}
	for _, stat := range stats {
		if stat == nil || stat.GetValue() <= 0 {
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
			item.Up = addStatCounter(item.Up, stat.GetValue())
		case "downlink":
			item.Down = addStatCounter(item.Down, stat.GetValue())
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

func QueryInboundStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]InboundStat, error) {
	stats, err := queryStats(apiHost, apiPort, timeout, "inbound>>>", reset)
	if err != nil {
		return nil, err
	}
	return inboundStatsFromCounters(stats), nil
}

func inboundStatsFromCounters(stats []*statscommand.Stat) []InboundStat {
	byTag := map[string]*InboundStat{}
	for _, stat := range stats {
		if stat == nil || stat.GetValue() <= 0 {
			continue
		}
		tag, link, ok := parseInboundStatName(stat.GetName())
		if !ok || strings.EqualFold(tag, "api") || strings.EqualFold(tag, "API_INBOUND") {
			continue
		}
		item := byTag[tag]
		if item == nil {
			item = &InboundStat{Tag: tag}
			byTag[tag] = item
		}
		switch link {
		case "uplink":
			item.Up = addStatCounter(item.Up, stat.GetValue())
		case "downlink":
			item.Down = addStatCounter(item.Down, stat.GetValue())
		}
	}

	tags := make([]string, 0, len(byTag))
	for tag := range byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	result := make([]InboundStat, 0, len(tags))
	for _, tag := range tags {
		item := byTag[tag]
		if item.Up != 0 || item.Down != 0 {
			result = append(result, *item)
		}
	}
	return result
}

func addStatCounter(current, delta int64) int64 {
	if delta <= 0 {
		return current
	}
	if current > math.MaxInt64-delta {
		return math.MaxInt64
	}
	return current + delta
}

func QueryUserStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]UserStat, error) {
	stats, err := queryStats(apiHost, apiPort, timeout, "user>>>", reset)
	if err != nil {
		return nil, err
	}
	return userStatsFromCounters(stats), nil
}

func userStatsFromCounters(stats []*statscommand.Stat) []UserStat {
	type userKey struct {
		uid        string
		inboundTag string
	}
	byUser := map[userKey]*UserStat{}
	for _, stat := range stats {
		if stat == nil || stat.GetValue() == 0 {
			continue
		}
		uid, inboundTag, link, ok := parseUserStatCounter(stat.GetName())
		if !ok {
			continue
		}
		key := userKey{uid: uid, inboundTag: inboundTag}
		item := byUser[key]
		if item == nil {
			item = &UserStat{UID: uid, InboundTag: inboundTag}
			byUser[key] = item
		}
		item.Value = addStatCounter(item.Value, stat.GetValue())
		switch link {
		case "uplink":
			item.Up = addStatCounter(item.Up, stat.GetValue())
		case "downlink":
			item.Down = addStatCounter(item.Down, stat.GetValue())
		}
	}

	keys := make([]userKey, 0, len(byUser))
	for key := range byUser {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].uid == keys[j].uid {
			return keys[i].inboundTag < keys[j].inboundTag
		}
		return keys[i].uid < keys[j].uid
	})

	result := make([]UserStat, 0, len(keys))
	for _, key := range keys {
		item := byUser[key]
		if item.Value != 0 {
			result = append(result, *item)
		}
	}
	return result
}

func QueryOnlineUserUIDs(apiHost string, apiPort int, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialAPI(ctx, apiHost, apiPort)
	if err != nil {
		return nil, fmt.Errorf("connect to Xray stats API: %w", err)
	}
	defer conn.Close()

	client := statscommand.NewStatsServiceClient(conn)
	res, err := client.GetAllOnlineUsers(ctx, &statscommand.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("query Xray online users: %w", err)
	}
	return onlineUserUIDs(res.GetUsers()), nil
}

func QueryOnlineUserSnapshot(apiHost string, apiPort int, timeout time.Duration) ([]string, []OnlineUserIP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialAPI(ctx, apiHost, apiPort)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to Xray stats API: %w", err)
	}
	defer conn.Close()

	client := statscommand.NewStatsServiceClient(conn)
	res, err := client.GetAllOnlineUsers(ctx, &statscommand.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("query Xray online users: %w", err)
	}
	uids := onlineUserUIDs(res.GetUsers())
	users, err := queryOnlineUserIPs(ctx, client, res.GetUsers())
	return uids, users, err
}

func onlineUserUIDs(names []string) []string {
	seen := map[string]struct{}{}
	for _, name := range names {
		_, uid, ok := parseOnlineUserName(name)
		if !ok {
			continue
		}
		seen[uid] = struct{}{}
	}

	uids := make([]string, 0, len(seen))
	for uid := range seen {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	return uids
}

func QueryOnlineUserIPs(apiHost string, apiPort int, timeout time.Duration) ([]OnlineUserIP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialAPI(ctx, apiHost, apiPort)
	if err != nil {
		return nil, fmt.Errorf("connect to Xray stats API: %w", err)
	}
	defer conn.Close()

	client := statscommand.NewStatsServiceClient(conn)
	res, err := client.GetAllOnlineUsers(ctx, &statscommand.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("query Xray online users: %w", err)
	}
	return queryOnlineUserIPs(ctx, client, res.GetUsers())
}

type onlineIPStatsClient interface {
	GetStatsOnlineIpList(context.Context, *statscommand.GetStatsRequest, ...grpc.CallOption) (*statscommand.GetStatsOnlineIpListResponse, error)
}

type onlineIPTask struct {
	statsName string
	email     string
	uid       string
}

const maxOnlineIPLookups = 512

func queryOnlineUserIPs(ctx context.Context, client onlineIPStatsClient, names []string) ([]OnlineUserIP, error) {
	tasks := make([]onlineIPTask, 0, len(names))
	for _, name := range names {
		statsName := strings.TrimSpace(name)
		email, uid, ok := parseOnlineUserName(statsName)
		if !ok {
			continue
		}
		if !strings.Contains(statsName, ">>>") {
			statsName = onlineUserStatsName(email)
		}
		tasks = append(tasks, onlineIPTask{statsName: statsName, email: email, uid: uid})
	}
	if len(tasks) == 0 {
		return nil, nil
	}
	if len(tasks) > maxOnlineIPLookups {
		// The UID list is the authoritative online signal. IP lookups are
		// supplementary and one RPC per user overwhelms Xray on large nodes.
		tasks = tasks[:maxOnlineIPLookups]
	}
	jobs := make(chan onlineIPTask, len(tasks))
	results := make(chan OnlineUserIP, len(tasks))
	errors := make(chan error, 1)
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)
	workers := min(8, len(tasks))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for task := range jobs {
				ipRes, err := client.GetStatsOnlineIpList(ctx, &statscommand.GetStatsRequest{Name: task.statsName})
				if err != nil {
					if status.Code(err) != codes.NotFound {
						select {
						case errors <- fmt.Errorf("query Xray online IPs for %s: %w", task.email, err):
						default:
						}
					}
					continue
				}
				ips := make([]OnlineIP, 0, len(ipRes.GetIps()))
				for ip, lastSeen := range ipRes.GetIps() {
					ip = strings.TrimSpace(ip)
					if ip != "" {
						ips = append(ips, OnlineIP{IP: ip, LastSeenUnix: lastSeen})
					}
				}
				sort.Slice(ips, func(i, j int) bool { return ips[i].IP < ips[j].IP })
				results <- OnlineUserIP{UID: task.uid, Email: task.email, IPs: ips}
			}
		}()
	}
	wg.Wait()
	close(results)

	users := make([]OnlineUserIP, 0, len(results))
	for user := range results {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].UID == users[j].UID {
			return users[i].Email < users[j].Email
		}
		return users[i].UID < users[j].UID
	})
	select {
	case err := <-errors:
		return users, err
	default:
		return users, nil
	}
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

const apiDialTimeout = 3 * time.Second

// ErrAPIUnavailable reports that the local Xray API could not be reached.
var ErrAPIUnavailable = errors.New("Xray API is unavailable")

func dialAPI(ctx context.Context, apiHost string, apiPort int) (*grpc.ClientConn, error) {
	host := strings.TrimSpace(apiHost)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, strconv.Itoa(apiPort))

	dialCtx, cancel := context.WithTimeout(ctx, apiDialTimeout)
	defer cancel()
	conn, err := grpc.DialContext(
		dialCtx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAPIUnavailable, err)
	}
	return conn, nil
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

func parseInboundStatName(name string) (string, string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 || parts[0] != "inbound" || parts[2] != "traffic" {
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
	uid, _, ok := parseUserStatIdentity(name)
	return uid, ok
}

func parseUserStatCounter(name string) (string, string, string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 {
		return "", "", "", false
	}
	uid, inboundTag, ok := parseUserStatIdentity(name)
	link := strings.ToLower(strings.TrimSpace(parts[3]))
	if !ok || (link != "uplink" && link != "downlink") {
		return "", "", "", false
	}
	return uid, inboundTag, link, true
}

func parseUserStatIdentity(name string) (string, string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", "", false
	}
	return parseUserEmailIdentity(parts[1])
}

func parseOnlineUserName(name string) (string, string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}
	if strings.HasPrefix(name, "user>>>") && strings.HasSuffix(name, ">>>online") {
		name = strings.TrimSuffix(strings.TrimPrefix(name, "user>>>"), ">>>online")
	}
	email := strings.TrimSpace(name)
	uid, ok := parseUserEmailUID(email)
	return email, uid, ok
}

func onlineUserStatsName(email string) string {
	return "user>>>" + strings.TrimSpace(email) + ">>>online"
}

func parseUserEmailUID(email string) (string, bool) {
	uid, _, ok := parseUserEmailIdentity(email)
	return uid, ok
}

func parseUserEmailIdentity(email string) (string, string, bool) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", "", false
	}
	uid, rest, hasRest := strings.Cut(email, ".")
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "", "", false
	}
	if !hasRest {
		return uid, "", true
	}
	marker, _, _ := strings.Cut(rest, ".")
	if !strings.HasPrefix(marker, inboundRuntimeEmailMarker) {
		return uid, "", true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(marker, inboundRuntimeEmailMarker))
	if err != nil || strings.TrimSpace(string(decoded)) == "" {
		return uid, "", true
	}
	return uid, string(decoded), true
}
