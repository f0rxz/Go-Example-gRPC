package main

import (
	netvulnv1 "GoNmap/internal/netvuln"
	"context"
	"errors"
	"github.com/Ullaakut/nmap"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"net"
	"strconv"
	"sync"
)

type server struct {
	netvulnv1.UnsafeNetVulnServiceServer
	logger *logrus.Logger
}

var (
	scanFailed    = errors.New("failed to create nmap scanner")
	runScanFailed = errors.New("failed to run nmap scanner")
)

func IntSliceToStringSlice(intSlice []int32) []string {
	strSlice := make([]string, len(intSlice))

	for i, v := range intSlice {
		strSlice[i] = strconv.Itoa(int(v))
	}

	return strSlice
}

func (s server) CheckVuln(ctx context.Context, request *netvulnv1.CheckVulnRequest) (*netvulnv1.CheckVulnResponse, error) {
	response := make([]*netvulnv1.TargetResult, 0)

	var mu sync.Mutex
	var wg sync.WaitGroup

	// TODO add some ping service to avoid wrong requests
	for _, t := range request.Targets {
		wg.Add(1)
		t := t
		go func(target string) {
			defer wg.Done()

			scanner, err := nmap.NewScanner(
				nmap.WithTargets(t),
				nmap.WithServiceInfo(),
				nmap.WithScripts("vulners"),
				nmap.WithPorts(IntSliceToStringSlice(request.TcpPort)...),
				nmap.WithContext(ctx),
			)
			if err != nil {
				mu.Lock()
				response = append(response, &netvulnv1.TargetResult{Target: scanFailed.Error()})
				mu.Unlock()
				return
			}

			result, warnings, err := scanner.Run()
			if err != nil {
				mu.Lock()
				response = append(response, &netvulnv1.TargetResult{Target: runScanFailed.Error()})
				mu.Unlock()
				return
			}
			if warnings != nil {
				s.logger.Info("Warnings:", warnings)
			}

			for _, host := range result.Hosts {
				if len(host.Ports) == 0 || len(host.Addresses) == 0 {
					continue
				}
				target := &netvulnv1.TargetResult{}

				s.logger.Info("Target IP: ", host.Addresses[0])
				target.Target = host.Addresses[0].String()

				for _, port := range host.Ports {
					s.logger.Info("Service: ", port.Service.Name, " ",
						port.Service.Product+port.Service.Version+port.Service.ExtraInfo, " ", port.ID)
					portVulners := make([]*netvulnv1.Vulnerability, 0)
					for _, vuln := range port.Scripts {
						if vuln.ID == "vulners" {
							for _, sc := range vuln.Tables {
								for _, v := range sc.Tables {
									vulnerability := &netvulnv1.Vulnerability{}
									s.logger.Info("vulnerability", v.Elements)
									for _, el := range v.Elements {
										if el.Key == "id" {
											vulnerability.Identifier = el.Value
										} else if el.Key == "cvss" {
											v, err := strconv.ParseFloat(el.Value, 32)
											if err != nil {
												s.logger.Info("wrong cvss score")
											}
											vulnerability.CvssScore = float32(v)
										}
									}
									portVulners = append(portVulners, vulnerability)
								}
							}
						}
					}
					target.Services = append(target.Services, &netvulnv1.Service{
						Name:    port.Service.Name,
						Version: port.Service.Product + " " + port.Service.Version + " " + port.Service.ExtraInfo,
						TcpPort: int32(port.ID),
						Vulns:   portVulners,
					})

				}
				mu.Lock()
				response = append(response, target)
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()

	return &netvulnv1.CheckVulnResponse{Results: response}, nil
}

func main() {
	logger := logrus.New()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("cmd/configs/")
	err := viper.ReadInConfig()
	if err != nil {
		logrus.Fatalln("Failed to read config file", err)
	}

	port := viper.GetString("server.port")
	switch viper.GetString("logging.level") {
	case "trace":
		logger.SetLevel(logrus.TraceLevel)
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logger.SetLevel(logrus.FatalLevel)
	case "panic":
		logger.SetLevel(logrus.PanicLevel)
	}

	listen, err := net.Listen("tcp", port)
	if err != nil {
		logger.Fatalln("Failed tp listen", err)
	}
	logger.Info("server is listening")
	serv := grpc.NewServer()
	netvulnv1.RegisterNetVulnServiceServer(serv, &server{logger: logger})

	if err := serv.Serve(listen); err != nil {
		logger.Fatalln("Failed to serve", err)
	}
	serv.GracefulStop()
}
