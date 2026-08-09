package service

import (
	"context"
	"fmt"

	"github.com/CyberTKR/line-go/api"
	"github.com/CyberTKR/line-go/protocol"
	"github.com/CyberTKR/line-go/transport"
)

type RefreshAccessTokenResponse struct {
	AccessToken               string
	DurationUntilRefreshInSec int64
	TokenIssueTimeEpochSec    int64
	RefreshToken              string
}

type AccessTokenRefresh struct{ service *Service }

func NewAccessTokenRefresh(client *transport.Client) *AccessTokenRefresh {
	return &AccessTokenRefresh{service: New(client, api.TokenRefreshPath)}
}

func (r *AccessTokenRefresh) Refresh(ctx context.Context, refreshToken, accessToken string) (RefreshAccessTokenResponse, error) {
	if refreshToken == "" {
		return RefreshAccessTokenResponse{}, fmt.Errorf("refresh token eksik")
	}
	result, err := r.service.Call(ctx, api.RefreshAccessTokenMethod, []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, refreshToken),
		}),
	}, accessToken)
	if err != nil {
		return RefreshAccessTokenResponse{}, err
	}
	return parseRefreshAccessTokenResponse(result)
}

func parseRefreshAccessTokenResponse(result any) (RefreshAccessTokenResponse, error) {
	fields, ok := result.(map[int16]any)
	if !ok {
		return RefreshAccessTokenResponse{}, fmt.Errorf("refresh: unexpected result %T", result)
	}
	response := RefreshAccessTokenResponse{
		AccessToken:               stringField(fields, 1),
		DurationUntilRefreshInSec: int64Field(fields, 2),
		TokenIssueTimeEpochSec:    int64Field(fields, 4),
		RefreshToken:              stringField(fields, 5),
	}
	if response.AccessToken == "" {
		return RefreshAccessTokenResponse{}, fmt.Errorf("refresh response does not contain an access token")
	}
	return response, nil
}
