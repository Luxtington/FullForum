package server

import (
	"AuthService/internal/service"
	"AuthService/proto"
	"context"
	"github.com/Luxtington/Shared/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

type GRPCServer struct {
	proto.UnimplementedAuthServiceServer
	authService *service.AuthService
}

func NewGRPCServer(authService *service.AuthService) *GRPCServer {
	return &GRPCServer{
		authService: authService,
	}
}

func (s *GRPCServer) ValidateToken(ctx context.Context, req *proto.ValidateTokenRequest) (*proto.ValidateTokenResponse, error) {
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, err
	}

	return &proto.ValidateTokenResponse{
		UserId:   uint32(user.ID),
		Username: user.Username,
		Role:     user.Role,
	}, nil
}

func (s *GRPCServer) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	user, token, err := s.authService.Register(req.Username, req.Email, req.Password)
	if err != nil {
		return nil, err
	}

	return &proto.RegisterResponse{
		UserId:   uint32(user.ID),
		Username: user.Username,
		Token:    token,
	}, nil
}

func (s *GRPCServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	user, token, err := s.authService.Login(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	return &proto.LoginResponse{
		UserId:   uint32(user.ID),
		Username: user.Username,
		Token:    token,
	}, nil
}

func StartGRPCServer(authService *service.AuthService, port string) error {
	log := logger.GetLogger()
	
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	proto.RegisterAuthServiceServer(grpcServer, NewGRPCServer(authService))

	log.Info("Starting gRPC server", zap.String("port", port))
	return grpcServer.Serve(lis)
} 