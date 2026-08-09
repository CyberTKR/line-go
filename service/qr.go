package service

import (
	"context"

	"github.com/CyberTKR/line-go/api"
	"github.com/CyberTKR/line-go/protocol"
	"github.com/CyberTKR/line-go/transport"
)

type QR struct {
	login  *Service
	permit *Service
}

func NewQR(client *transport.Client) *QR {
	return &QR{
		login:  New(client, api.QRLoginPath),
		permit: New(client, api.QRPermitPath),
	}
}

func (q *QR) CreateSession(ctx context.Context) (any, error) {
	return q.login.Call(ctx, "createSession", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{}),
	}, "")
}

func (q *QR) CreateSecureCode(ctx context.Context, sessionID string) (any, error) {
	return q.login.Call(ctx, "createQrCodeForSecure", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, sessionID),
		}),
	}, "")
}

func (q *QR) CheckCodeVerified(ctx context.Context, sessionID string) error {
	_, err := q.permit.Call(ctx, "checkQrCodeVerified", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, sessionID),
		}),
	}, sessionID)
	return err
}

func (q *QR) VerifyCertificate(ctx context.Context, sessionID, certificate string) error {
	_, err := q.login.Call(ctx, "verifyCertificate", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, sessionID),
			protocol.F(2, protocol.String, certificate),
		}),
	}, "")
	return err
}

func (q *QR) CreatePIN(ctx context.Context, sessionID string) (any, error) {
	return q.login.Call(ctx, "createPinCode", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, sessionID),
		}),
	}, "")
}

func (q *QR) CheckPINVerified(ctx context.Context, sessionID string) error {
	_, err := q.permit.Call(ctx, "checkPinCodeVerified", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, sessionID),
		}),
	}, sessionID)
	return err
}

func (q *QR) LoginV2(ctx context.Context, sessionID, systemName, modelName, nonce string) (any, error) {
	return q.login.Call(ctx, "qrCodeLoginV2ForSecure", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, sessionID),
			protocol.F(2, protocol.String, systemName),
			protocol.F(3, protocol.String, modelName),
			protocol.F(4, protocol.Bool, true),
			protocol.F(5, protocol.String, nonce),
		}),
	}, "")
}
