package utils

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/common/promlog"
)

func cmdCommand(cmdStr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.Trim(string(out), "\n"), nil
}

func GetIP() (string, error) {
	gateway, _ := getGateway()
	level.Info(promlog.New(&promlog.Config{})).Log("host gateway ", gateway)
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		if strings.Contains(iface.Name, "docker") || strings.Contains(iface.Name, "veth") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			addr.Network()

			ip := getIpFromAddr(addr)
			if ip == nil {
				continue
			}

			if getRealIp(ip.String(), gateway) {
				return ip.String(), nil
			}

		}
	}
	return "", errors.New("connected to the network?")
}

func getIpFromAddr(addr net.Addr) net.IP {
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil // not an ipv4 address
	}
	return ip
}

func getGateway() (string, error) {
	cmd1 := "ip route show | grep default | awk '{print $3}'"
	cmd2 := "route -n | grep ^0.0.0.0 | awk '{print $2}'"
	gs, err := cmdCommand(cmd1)
	if err != nil {
		gs, err = cmdCommand(cmd2)
		if err != nil {
			return "", err
		}
	}

	tmp := strings.Split(gs, "\n")
	if len(tmp) > 1 {
		return tmp[0], nil
	}
	return gs, nil
}

func getRealIp(sip, dip string) bool {
	cmd := fmt.Sprintf("ping -I %s %s -c 1", sip, dip)
	level.Info(promlog.New(&promlog.Config{})).Log("ping cmd", cmd)
	_, err := cmdCommand(cmd)
	if err != nil {
		level.Info(promlog.New(&promlog.Config{})).Log("ping cmd failed %v", err)
		return false
	}
	return true
}
