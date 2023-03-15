package main

import (
	netvulnv1 "GoNmap/internal/netvuln"
	"context"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"strings"
)

func main() {
	logger := logrus.New()

	conn, err := grpc.Dial(":5000",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Info("can't connect to server: %v", err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			logger.Fatalln(err)
		}
	}(conn)

	client := netvulnv1.NewNetVulnServiceClient(conn)
	logger.Info("created client: %v", client)

	res, err := client.CheckVuln(context.Background(), &netvulnv1.CheckVulnRequest{
		Targets: []string{"scanme.nmap.org"},
		TcpPort: []int32{80},
	})
	if err != nil {
		if strings.Contains(err.Error(), "connection closed") {
			logger.Fatalln("server shutdown")
		} else {
			logger.Fatalln("failed to call gRPC method: ", err)
		}
	}
	logger.Info(res.Results)
}
