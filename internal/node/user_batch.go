package node

import (
	"context"
	"errors"
	"fmt"
	"strings"

	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxUserBatchOperations = 1000

func (api *grpcAPI) ApplyUserBatch(ctx context.Context, req *nodev1.UserBatchRequest) (*nodev1.UserBatchResponse, error) {
	operations := req.GetOperations()
	if len(operations) > maxUserBatchOperations {
		return nil, status.Errorf(codes.InvalidArgument, "user batch exceeds %d operations", maxUserBatchOperations)
	}
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	response := &nodev1.UserBatchResponse{BatchId: req.GetBatchId(), Results: make([]*nodev1.UserBatchResult, 0, len(operations))}
	if len(operations) == 0 {
		return response, nil
	}
	if !api.server.core.Started() {
		return nil, status.Error(codes.FailedPrecondition, "Xray is not started")
	}
	for index, operation := range operations {
		if err := ctx.Err(); err != nil {
			return nil, status.FromContextError(err).Err()
		}
		result, err := api.server.applyUserBatchOperation(operation)
		response.Results = append(response.Results, result)
		if errors.Is(err, xray.ErrAPIUnavailable) {
			for range operations[index+1:] {
				response.Results = append(response.Results, failedUserBatchResult("not attempted: Xray API is unavailable"))
			}
			break
		}
	}
	return response, nil
}

func (s *Server) applyUserBatchOperation(operation *nodev1.UserBatchOperation) (*nodev1.UserBatchResult, error) {
	inboundTag := strings.TrimSpace(operation.GetInboundTag())
	if inboundTag == "" {
		return failedUserBatchResult("inbound_tag is required"), nil
	}
	var err error
	switch operation.GetAction() {
	case nodev1.UserBatchAction_USER_BATCH_ACTION_UPSERT:
		var user xray.InboundUser
		user, err = protoInboundUser(operation.GetUser())
		if err == nil {
			err = s.upsertBatchUser(inboundTag, user)
		}
	case nodev1.UserBatchAction_USER_BATCH_ACTION_REMOVE:
		err = s.removeBatchUser(inboundTag, strings.TrimSpace(operation.GetEmail()))
	default:
		err = fmt.Errorf("unsupported user batch action %s", operation.GetAction())
	}
	if err != nil {
		return failedUserBatchResult(status.Convert(err).Message()), err
	}
	return &nodev1.UserBatchResult{Ok: true}, nil
}

func failedUserBatchResult(message string) *nodev1.UserBatchResult {
	return &nodev1.UserBatchResult{Ok: false, Error: message}
}

func (s *Server) upsertBatchUser(inboundTag string, user xray.InboundUser) error {
	previous, exists, cacheAvailable, err := s.cachedConfigUser(inboundTag, user.Email)
	if err != nil {
		return err
	}
	user, err = s.inheritInboundUserFlow(inboundTag, user)
	if err != nil {
		return err
	}
	if !cacheAvailable {
		if err := xray.AddInboundUser(s.settings.XrayAPIHost, s.settings.XrayAPIPort, grpcOperationTimeout, inboundTag, user); err != nil && !isIgnorableXrayAddError(err) {
			return err
		}
		return s.addUserToConfigCache(inboundTag, user)
	}
	diff := configUserDiffResult{}
	if exists {
		diff.update = append(diff.update, configUserUpdate{inboundTag: inboundTag, previous: previous, current: user})
	} else {
		diff.add = append(diff.add, configUserAdd{inboundTag: inboundTag, user: user})
	}
	if err := s.applyConfigUserDiffResult(diff); err != nil {
		return err
	}
	return s.addUserToConfigCache(inboundTag, user)
}

func (s *Server) removeBatchUser(inboundTag string, email string) error {
	if email == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if err := xray.RemoveInboundUser(s.settings.XrayAPIHost, s.settings.XrayAPIPort, grpcOperationTimeout, inboundTag, email); err != nil && !isIgnorableXrayRemoveError(err) {
		return err
	}
	return s.removeUserFromConfigCache(inboundTag, email)
}
