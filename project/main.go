package main

// test comment
import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"

	_ "gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-scion/lib"
)

// The local IP address of your endhost.
// It matches the IP address of the SCION daemon you should use for this run.
var local string

// The remote SCION address of the verifier application.
var remote snet.UDPAddr

// The port of your SCION daemon.
const daemonPort = 30255

func main() {
	// DO NOT MODIFY THIS FUNCTION
	err := log.Setup(log.Config{
		Console: log.ConsoleConfig{
			Level:           "DEBUG",
			StacktraceLevel: "none",
		},
	})
	if err != nil {
		fmt.Println(serrors.WrapStr("setting up logging", err))
	}
	flag.StringVar(&local, "local", "", "The local IP address which is the same IP as the IP of the local SCION daemon")
	flag.Var(&remote, "remote", "The address of the validator")
	flag.Parse()

	if err := realMain(); err != nil {
		log.Error("Error while running project", "err", err)
	}
}

func realMain() error {
	// Your code starts here.

	// create ctx.Context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// create daemon addr - daemon always runs on localhost
	var daemonAddr string
	if strings.Contains(local, ":") {
		// IPv6 address - wrap in brackets
		daemonAddr = fmt.Sprintf("[%s]:%d", local, daemonPort)
	} else {
		// IPv4 address
		daemonAddr = fmt.Sprintf("%s:%d", local, daemonPort)
	}
	daemonService := daemon.Service{Address: daemonAddr}
	// connect to daemon
	daemonConnector, err := daemonService.Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}

	// get Local IA address
	localIAAddr, err := daemonConnector.LocalIA(ctx)
	if err != nil {
		return serrors.WrapStr("getting local IA", err)
	}
	// create source UDPAddr
	localAddr := &snet.UDPAddr{
		IA:   localIAAddr,
		Host: &net.UDPAddr{IP: net.ParseIP(local), Port: 0}, // according to net documentation setting port to zero force the system to choose an available port
	}

	// log local IA address
	log.Debug("Local IA address", "localIA", localIAAddr)
	log.Debug("Local address", "localAddr", localAddr)

	pathsToVerIA, err := daemonConnector.Paths(ctx, remote.IA, localIAAddr, daemon.PathReqFlags{})
	if err != nil {
		return serrors.WrapStr("getting paths to verifier IA", err)
	}

	// Handle no available paths - terminate execution if no paths found
	if len(pathsToVerIA) == 0 {
		log.Error("No paths available to verifier IA", "verifierIA", remote.IA, "localIA", localIAAddr)
		return serrors.New("no paths available to destination")
	}

	// log paths one per line
	log.Debug("Paths to verifier IA", "count", len(pathsToVerIA))
	for i, path := range pathsToVerIA {
		log.Debug("Path", "index", i, "path", path)
	}

	// extend remote, with next hop(this AS border router) and one dataplane path
	// Check if destination is in a remote AS (more than one segment in path indicates crossing AS boundaries)
	isRemoteAS := len(pathsToVerIA) > 0 && pathsToVerIA[0].Source() != pathsToVerIA[0].Destination()
	if isRemoteAS {
		remote.NextHop = pathsToVerIA[0].UnderlayNextHop()
		remote.Path = pathsToVerIA[0].Dataplane()
		log.Debug("Remote AS detected, setting path and next hop")
	} else {
		log.Debug("Same AS communication, no path extension needed")
	}

	// establish connection with the verifier
	// TODO check if I should set ReplyPatcher and SCMPhandler too.
	scionNetwork := &snet.SCIONNetwork{Topology: daemonConnector}
	spktConn, err := scionNetwork.OpenRaw(ctx, localAddr.Host)
	if err != nil {
		return serrors.WrapStr("opening packet connection", err)
	}

	log.Debug("opened raw conection bound to underlay", spktConn.LocalAddr)

	// conn, err := scionNetwork.Dial(ctx, "udp", localAddr.Host, &remote)
	// if err != nil {
	// 	return serrors.WrapStr("dialing to verifier", err)
	// }

	// craft SCION datagram payload according to test tasks
	payloadBytes := []byte(`{"ID": 1,"Payload": {}}`)

	// craft full SCION packet
	srcNetIPAddr, err := netip.ParseAddr(localAddr.Host.IP.String())
	if err != nil {
		return serrors.WrapStr("parsing local IP address", err)
	}
	dstNetIPAddr, err := netip.ParseAddr(remote.Host.IP.String())
	if err != nil {
		return serrors.WrapStr("parsing remote IP address", err)
	}
	send_packet := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcNetIPAddr),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstNetIPAddr),
			},
			Path:    pathsToVerIA[0].Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(spktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
		},
	}

	// send crafted packer with write and listen for replies from teh verifier
	err = spktConn.WriteTo(&send_packet, pathsToVerIA[0].UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}
	log.Debug("sent to remote :", scionNetwork.Metrics.Dials)
	receive_packet := snet.Packet{}
	var sender_underlay net.UDPAddr
	err = spktConn.ReadFrom(&receive_packet, &sender_underlay)
	if err != nil {
		return serrors.WrapStr("reading message from connection", err)
	}

	// Extract payload from received packet
	var replyPayload []byte
	if udpPayload, ok := receive_packet.Payload.(snet.UDPPayload); ok {
		replyPayload = udpPayload.Payload
		log.Debug("Received UDP payload", "length", len(replyPayload), "data", string(replyPayload))
	} else {
		log.Debug("Received non-UDP payload", "type", fmt.Sprintf("%T", receive_packet.Payload))
		// For non-UDP payloads, we can't easily extract the payload without more complex parsing
		replyPayload = []byte{}
	}

	log.Debug("Parsed reply payload", "payload", string(replyPayload))

	defer spktConn.Close()

	return nil
}
