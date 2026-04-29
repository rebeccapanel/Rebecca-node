package xray

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

type stat struct {
	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value int64  `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (s *stat) Reset()         { *s = stat{} }
func (s *stat) String() string { return proto.CompactTextString(s) }
func (*stat) ProtoMessage()    {}

type queryStatsRequest struct {
	Pattern string `protobuf:"bytes,1,opt,name=pattern,proto3" json:"pattern,omitempty"`
	Reset_  bool   `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (r *queryStatsRequest) Reset()         { *r = queryStatsRequest{} }
func (r *queryStatsRequest) String() string { return proto.CompactTextString(r) }
func (*queryStatsRequest) ProtoMessage()    {}

type queryStatsResponse struct {
	Stat []*stat `protobuf:"bytes,1,rep,name=stat,proto3" json:"stat,omitempty"`
}

func (r *queryStatsResponse) Reset()         { *r = queryStatsResponse{} }
func (r *queryStatsResponse) String() string { return proto.CompactTextString(r) }
func (*queryStatsResponse) ProtoMessage()    {}

func QueryOutboundStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]OutboundStat, error) {
	res, err := queryStats(apiHost, apiPort, timeout, "outbound>>>", reset)
	if err != nil {
		return nil, err
	}

	byTag := map[string]*OutboundStat{}
	for _, stat := range res.Stat {
		tag, link, ok := parseOutboundStatName(stat.Name)
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
			item.Up += stat.Value
		case "downlink":
			item.Down += stat.Value
		}
	}

	result := make([]OutboundStat, 0, len(byTag))
	for _, item := range byTag {
		if item.Up != 0 || item.Down != 0 {
			result = append(result, *item)
		}
	}
	return result, nil
}

func QueryUserStats(apiHost string, apiPort int, timeout time.Duration, reset bool) ([]UserStat, error) {
	res, err := queryStats(apiHost, apiPort, timeout, "user>>>", reset)
	if err != nil {
		return nil, err
	}

	byUID := map[string]int64{}
	for _, stat := range res.Stat {
		uid, ok := parseUserStatName(stat.Name)
		if !ok || stat.Value == 0 {
			continue
		}
		byUID[uid] += stat.Value
	}

	result := make([]UserStat, 0, len(byUID))
	for uid, value := range byUID {
		if value != 0 {
			result = append(result, UserStat{UID: uid, Value: value})
		}
	}
	return result, nil
}

func queryStats(apiHost string, apiPort int, timeout time.Duration, pattern string, reset bool) (*queryStatsResponse, error) {
	host := strings.TrimSpace(apiHost)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, strconv.Itoa(apiPort))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to Xray stats API: %w", err)
	}
	defer conn.Close()

	res := &queryStatsResponse{}
	err = conn.Invoke(ctx, "/xray.app.stats.command.StatsService/QueryStats", &queryStatsRequest{
		Pattern: pattern,
		Reset_:  reset,
	}, res)
	if err != nil {
		return nil, fmt.Errorf("query Xray stats: %w", err)
	}
	return res, nil
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
