package main

// test comment
import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	fabridcommon "github.com/scionproto/scion/pkg/experimental/fabrid/common"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-scion/lib"
)

// The local IP address of your endhost.
// It matches the IP address of the SCION daemon you should use for this run.
var local string

// The remote SCION address of the verifier application.
var remote snet.UDPAddr

var daemonConnectorGlobal daemon.Connector

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

func test1(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, pathToVer snet.Path) error {

	// craft SCION datagram payload according to test task
	payloadBytes := []byte(`{"ID": 1,"Payload": {}}`)

	send_packet := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcIP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstIP),
			},
			Path:    pathToVer.Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	// send crafted packer with write and listen for replies from teh verifier
	log.Debug("about to write packet", "SCION datagram", send_packet)
	err := sPktConn.WriteTo(&send_packet, pathToVer.UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}

	receive_packet := snet.Packet{}
	var sender_underlay net.UDPAddr
	err = sPktConn.ReadFrom(&receive_packet, &sender_underlay)
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

	// TODO edit debgu log to printout test execiution result
	log.Debug("Verifier reply UDPPayload", "payload", string(replyPayload))

	return nil
}

func test2(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, pathsToVer []snet.Path) error {

	// craft SCION datagram payload according to test task
	payloadBytes := []byte(`{"ID": 2,"Payload": {}}`)

	path := pathsToVer[0]

	send_packet := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcIP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstIP),
			},
			Path:    pathsToVer[0].Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	// send crafted packer with write and listen for replies from teh verifier
	err := sPktConn.WriteTo(&send_packet, path.UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}

	receive_packet := snet.Packet{}
	var sender_underlay net.UDPAddr
	err = sPktConn.ReadFrom(&receive_packet, &sender_underlay)
	if err != nil {
		return serrors.WrapStr("reading message from connection", err)
	}

	// Extract payload from received packet
	var replyPayload []byte
	udpPayload, ok := receive_packet.Payload.(snet.UDPPayload)
	if ok {
		replyPayload = udpPayload.Payload
		log.Debug("Received UDP payload", "length", len(replyPayload), "data", string(replyPayload))
	} else {
		log.Debug("Received non-UDP payload", "type", fmt.Sprintf("%T", receive_packet.Payload))
		// For non-UDP payloads, we can't easily extract the payload without more complex parsing
		replyPayload = []byte{}
	}
	log.Debug("Parsed reply payload", "payload", string(replyPayload))

	var result lib.TestResult
	if err := json.Unmarshal(replyPayload, &result); err != nil {
		log.Debug("failed to decode verifier reply: %v", err)
	}

	testStatus := result.State
	requiredAddpackets := result.Payload.(float64)

	log.Debug("Initial test status", "status", testStatus, "requiredAddpackets", requiredAddpackets)

	// loop while (testStatus == lib.TestState.TestRunning)
	for testStatus == lib.TestRunning {
		log.Debug("Sending additional packet", "remaining_packets", requiredAddpackets)

		pathsToVer = pathsToVer[1:]

		// craft new packet identical to the previous one
		send_packet := snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   localIAAddr,
					Host: addr.HostIP(srcIP),
				},
				Destination: snet.SCIONAddress{
					IA:   remote.IA,
					Host: addr.HostIP(dstIP),
				},
				Path:    pathsToVer[0].Dataplane(), // path retrieved from daemon
				Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
			},
		}

		// send another packet
		err = sPktConn.WriteTo(&send_packet, path.UnderlayNextHop())
		if err != nil {
			return serrors.WrapStr("sending additional scion msg to verifier", err)
		}

		// read it
		receive_packet := snet.Packet{}
		var sender_underlay net.UDPAddr
		err = sPktConn.ReadFrom(&receive_packet, &sender_underlay)
		if err != nil {
			return serrors.WrapStr("reading additional message from connection", err)
		}

		// Extract payload from received packet
		udpPayload, ok := receive_packet.Payload.(snet.UDPPayload)
		if !ok {
			return serrors.WrapStr("received non-UDP payload in loop", fmt.Errorf("expected UDP payload, got %T", receive_packet.Payload))
		}
		replyPayload := udpPayload.Payload

		var result lib.TestResult
		if err := json.Unmarshal(replyPayload, &result); err != nil {
			return serrors.WrapStr("failed to decode verifier reply in loop", err)
		}

		// update testStatus with received packet udppayload state like previously
		testStatus = result.State
		// needed for debugging with output
		// requiredAddpackets, ok = result.Payload.(float64)
		// if !ok {
		//	return serrors.WrapStr("No additional packets required, got %T", requiredAddpackets)
		// } else {
		//  log.Debug("Updated test status", "status", testStatus, "requiredAddpackets", requiredAddpackets)
		// }
	}

	log.Debug("Test completed", "final_status", testStatus)
	return nil
}

func findLeastCarbonIntensityPath(pathsToVer []snet.Path, maxMissingCarbonIntensityHops int) (bool, snet.Path) {
	log.Debug("Finding least carbon intensity path", "maxMissingHops", maxMissingCarbonIntensityHops, "totalPaths", len(pathsToVer))

	var eligiblePaths []snet.Path = nil
	//  find 1 or more path(s) with number of hops with ci==-1 == maxMissingCarbonIntensityHops
	for _, path := range pathsToVer {
		pathMeta := path.Metadata()
		var pathMissingCIHops int = 0
		for _, ci := range pathMeta.CarbonIntensity {
			if ci < 0 {
				pathMissingCIHops++
			}
		}
		log.Debug("Path evaluated", "missingHops", pathMissingCIHops, "carbonIntensity", pathMeta.CarbonIntensity)
		if pathMissingCIHops == maxMissingCarbonIntensityHops {
			eligiblePaths = append(eligiblePaths, path)
			log.Debug("Eligible path found", "count", len(eligiblePaths))
		}
	}

	// if none is found return false, nil
	if len(eligiblePaths) == 0 {
		log.Debug("No eligible paths found")
		var zeroPath snet.Path
		return false, zeroPath
	}

	// if only one is found len(eligiblePaths) == 1 return it with true
	if len(eligiblePaths) == 1 {
		log.Debug("Single eligible path found")
		return true, eligiblePaths[0]
	}

	// if more than one is found, find the path with the lowest ci sum
	minCIsum := int64(0)
	minCIPathIndex := 0
	for i, path := range eligiblePaths {
		pathMeta := path.Metadata()
		var ciSum int64 = 0
		for _, ci := range pathMeta.CarbonIntensity {
			if ci >= 0 {
				ciSum += ci
			}
		}
		log.Debug("Path CI sum calculated", "index", i, "sum", ciSum)
		if i == 0 || ciSum < minCIsum {
			minCIsum = ciSum
			minCIPathIndex = i
		}
	}

	log.Debug("Lowest CI sum path selected", "sum", minCIsum, "pathIndex", minCIPathIndex)
	// return it with true
	return true, eligiblePaths[minCIPathIndex]
}

//  firstly find any path with all interfaces having carbon impact reduction enabled --> I seem to be able to get full path carbonImpactsum from one path
//  --> len(TotalInterfaces) == len(carbonintensity-(-1 values)) ?
// interface = interface on the border rotuer(hop), each router has two interfaces(egress, ingress)
// path.metadata().CarbonIntensity(i) returns carbon intensity value from interface i and i+1, -1 is not enabled --> is it a sum of the two infs? do I need of single infs?
// path.metdata().interfaces(i) returns i-th interface which exposes its carbonintensity accordgin to gpt

// if at least one path with full carbon impact reduction coverage is found send over it

// otherwise
// slice to paths having the lowest number of missing carbon intensity reduction interfaces
// choose the one with the lowest oevrall sum, which will be the shortest one among the sliced paths
// send over it
func test10(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, pathsToVer []snet.Path) error {

	foundLeastCarbonIntensitypath := false
	var path snet.Path
	i := 0
	for !foundLeastCarbonIntensitypath {
		foundLeastCarbonIntensitypath, path = findLeastCarbonIntensityPath(pathsToVer, i)
		i++
	}

	payloadBytes := []byte(`{"ID": 10,"Payload": {}}`)

	send_packet := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcIP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstIP),
			},
			Path:    path.Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	// send crafted packer with write and listen for replies from teh verifier
	err := sPktConn.WriteTo(&send_packet, path.UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}

	receive_packet := snet.Packet{}
	var sender_underlay net.UDPAddr
	err = sPktConn.ReadFrom(&receive_packet, &sender_underlay)
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

	log.Debug("Verifier reply UDPPayload", "payload", string(replyPayload))

	return nil
}

func findLexicographicLowestIntfIdsPath(pathsToVer []snet.Path) snet.Path {
	if len(pathsToVer) == 0 {
		return nil
	}

	// Find the path with the lexicographically lowest interface ID sequence
	minPath := pathsToVer[0]

	for _, path := range pathsToVer[1:] {
		// Compare interface IDs lexicographically
		minInterfaces := minPath.Metadata().Interfaces
		pathInterfaces := path.Metadata().Interfaces

		// Compare up to the length of the shorter path
		minLen := len(minInterfaces)
		if len(pathInterfaces) < minLen {
			minLen = len(pathInterfaces)
		}

		isBetter := false
		for i := 0; i < minLen; i++ {
			minID := uint64(minInterfaces[i].ID)
			pathID := uint64(pathInterfaces[i].ID)

			if pathID < minID {
				isBetter = true
				break
			} else if pathID > minID {
				// Current path has larger ID at this position, keep current minPath
				isBetter = false
				break
			}
			// If IDs are equal, continue to next interface
		}

		// If we didn't find a difference in the common length,
		// the shorter path wins (lexicographically smaller)
		if len(pathInterfaces) < len(minInterfaces) && minLen == len(pathInterfaces) {
			isBetter = true
		}

		if isBetter {
			minPath = path
		}
	}

	return minPath
}

func findShortestPaths(pathsToVer []snet.Path) []snet.Path {
	if len(pathsToVer) == 0 {
		return nil
	}

	// Find the minimum path length
	minLength := len(pathsToVer[0].Metadata().Interfaces)
	for _, path := range pathsToVer {
		pathLen := len(path.Metadata().Interfaces)
		if pathLen < minLength {
			minLength = pathLen
		}
	}

	// Collect all paths with the minimum length
	var shortestPaths []snet.Path
	for _, path := range pathsToVer {
		if len(path.Metadata().Interfaces) == minLength {
			shortestPaths = append(shortestPaths, path)
		}
	}

	return shortestPaths
}

func findHigherBandwidthPaths(pathsToVer []snet.Path) []snet.Path {

	var higherBwPaths []snet.Path
	var higherBw uint64 = 0

	// First pass: find the maximum minimum (bottleneck) bandwidth among all paths
	for _, path := range pathsToVer {
		pathMeta := path.Metadata()
		var minPathBw uint64 = 0
		for _, bw := range pathMeta.Bandwidth {
			if bw != 0 && (minPathBw == 0 || bw < minPathBw) {
				minPathBw = bw
			}
		}
		if minPathBw > higherBw {
			higherBw = minPathBw
		}
	}

	// Second pass: collect all paths that have this maximum minimum bandwidth
	for _, path := range pathsToVer {
		pathMeta := path.Metadata()
		var minPathBw uint64 = 0
		for _, bw := range pathMeta.Bandwidth {
			if bw != 0 && (minPathBw == 0 || bw < minPathBw) {
				minPathBw = bw
			}
		}
		if minPathBw == higherBw {
			higherBwPaths = append(higherBwPaths, path)
		}
	}

	return higherBwPaths
}

func findHigherBandwidthBoundedLeastLatencyPath(pathsToVer []snet.Path, maxMissingLtHops int) (bool, snet.Path) {

	// latency or bandwidth not announced by AS for the relative hop -> 0 value in respective lists
	// as of test cse description In this case and only in this case, assume that all interfaces that are missing bandwidth information are not limiting the path bandwidth.

	var eligibleFullyAnnouncedLtBwPaths []snet.Path = nil
	var eligibleFullyAnnouncedLtPaths []snet.Path = nil
	var eligiblePartiallyAnnouncedLtPaths []snet.Path = nil
	for _, path := range pathsToVer {
		pathMeta := path.Metadata()
		var pathMissingLtHops int = 0
		for _, lt := range pathMeta.Latency {
			if lt == -1 {
				pathMissingLtHops++
			}
		}
		if pathMissingLtHops == maxMissingLtHops && maxMissingLtHops == 0 {
			// if we are checking latency announcement for all hops, check if all are also announcing bandwidth
			var pathMissingBwHops int = 0
			for _, bw := range pathMeta.Bandwidth {
				if bw == 0 {
					pathMissingBwHops++
				}
			}
			if pathMissingBwHops == 0 { // ideal scenario latency and bandwidth fully announced by all hops, path(s) have priority over all other
				eligibleFullyAnnouncedLtBwPaths = append(eligibleFullyAnnouncedLtBwPaths, path)
			} else { // path might announce all latencies but missing bandwidths, still eligible - how to handle this?
				eligibleFullyAnnouncedLtPaths = append(eligibleFullyAnnouncedLtPaths, path)
			}
			// not checking for latency announmcent from all hops, therefore neither full bandwidth announcemnt is needed
		} else if pathMissingLtHops == maxMissingLtHops {
			eligiblePartiallyAnnouncedLtPaths = append(eligiblePartiallyAnnouncedLtPaths, path)
		}
	}
	// no path found with number of hops missing latency announcement == maxMissingLtHops
	var _pathsToVer []snet.Path = nil
	if len(eligibleFullyAnnouncedLtBwPaths) == 0 && len(eligibleFullyAnnouncedLtPaths) == 0 && len(eligiblePartiallyAnnouncedLtPaths) == 0 {
		return false, nil
	} else if len(eligibleFullyAnnouncedLtBwPaths) != 0 {
		_pathsToVer = findHigherBandwidthPaths(eligibleFullyAnnouncedLtBwPaths)
	} else if len(eligibleFullyAnnouncedLtPaths) != 0 {
		_pathsToVer = findHigherBandwidthPaths(eligibleFullyAnnouncedLtPaths)
	} else { // eligiblePartiallyAnnouncedLtPaths found
		_pathsToVer = findHigherBandwidthPaths(eligiblePartiallyAnnouncedLtPaths)
	}
	if len(_pathsToVer) == 1 {
		return true, _pathsToVer[0]
	} else { // additional slice based on shortest path
		var __pathsToVer []snet.Path = nil
		__pathsToVer = findShortestPaths(_pathsToVer)
		if len(__pathsToVer) == 1 {
			return true, __pathsToVer[0]
		} else { // additional slice based on minimum first hop interface ID
			var ___pathsToVer snet.Path = nil
			___pathsToVer = findLexicographicLowestIntfIdsPath(__pathsToVer)
			return true, ___pathsToVer
		}
	}

}

func test11(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, pathsToVer []snet.Path) error {

	// send simple packet with testid 11
	// parse latencyBound with UDPPayload payload of reply

	payloadBytes := []byte(`{"ID": 11,"Payload": {}}`)

	send_sample_packet := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcIP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstIP),
			},
			Path:    pathsToVer[0].Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	// send crafted packer with write and listen for replies from teh verifier
	err := sPktConn.WriteTo(&send_sample_packet, pathsToVer[0].UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}

	receive_sample_packet := snet.Packet{}
	var sample_sender_underlay net.UDPAddr
	err = sPktConn.ReadFrom(&receive_sample_packet, &sample_sender_underlay)
	if err != nil {
		return serrors.WrapStr("reading message from connection", err)
	}

	// Extract payload from received packet
	var sampleReplyPayload []byte
	udpPayload, ok := receive_sample_packet.Payload.(snet.UDPPayload)
	if ok {
		sampleReplyPayload = udpPayload.Payload
		log.Debug("Received UDP payload", "length", len(sampleReplyPayload), "data", string(sampleReplyPayload))
	} else {
		log.Debug("Received non-UDP payload", "type", fmt.Sprintf("%T", receive_sample_packet.Payload))
		// For non-UDP payloads, we can't easily extract the payload without more complex parsing
		sampleReplyPayload = []byte{}
	}
	log.Debug("Parsed reply payload", "payload", string(sampleReplyPayload))

	var testPayload lib.TestResult
	if err := json.Unmarshal(sampleReplyPayload, &testPayload); err != nil {
		log.Debug("failed to decode verifier reply: %v", err)
	}
	// verifier will respond with an integer as payload indicating the maximum latency in milliseconds
	latencyBoundms := testPayload.Payload.(float64) // TODO maybe type asserting an attribute of an object parsed json isn't correct
	log.Debug("received latency bound", "latencyBoundms", float64(latencyBoundms))
	// fitler out paths with latencyms > then latencyBoundms

	// compute total latency of all paths slice out paths that have higher than bound
	var pathsToVerLtCompliant []snet.Path = nil
	for _, _path := range pathsToVer {
		var _pathTotalLt time.Duration = 0
		for _, lt := range _path.Metadata().Latency {
			if lt != -1 {
				_pathTotalLt += lt
			}
		}
		_pathTotalLtms := float64(_pathTotalLt.Nanoseconds()) / 1e6
		if _pathTotalLtms <= latencyBoundms {
			pathsToVerLtCompliant = append(pathsToVerLtCompliant, _path)
		}
	}
	// we assume at least one path has totalLatency < bound

	var maxMisingLtHops int = 0
	var foundHigherBwLeastLtpath bool = false
	var path snet.Path = nil
	for !foundHigherBwLeastLtpath {
		foundHigherBwLeastLtpath, path = findHigherBandwidthBoundedLeastLatencyPath(pathsToVerLtCompliant, maxMisingLtHops)
		maxMisingLtHops++
	}

	send_packet := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcIP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstIP),
			},
			Path:    path.Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	// send crafted packer with write and listen for replies from teh verifier
	err = sPktConn.WriteTo(&send_packet, path.UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}

	receive_packet := snet.Packet{}
	var sender_underlay net.UDPAddr
	err = sPktConn.ReadFrom(&receive_packet, &sender_underlay)
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

	log.Debug("Verifier reply UDPPayload", "payload", string(replyPayload))

	return nil
}

func findHiddenPathsSupportingEPIC(hiddenPaths []snet.Path) []snet.Path {

	// check that hiddenPaths isn't empty
	// looop through all paths : if both _path.Metadata().EpicAuths.AuthLHVF and _path.Metadata().EpicAuths.AuthPHVF are not nil path support EPIC
	// add to returning list and return it
	var epicPaths []snet.Path
	if len(hiddenPaths) == 0 {
		return epicPaths
	}
	for _, hiddenPath := range hiddenPaths {
		metadata := hiddenPath.Metadata()
		if metadata == nil {
			continue
		}
		if metadata.EpicAuths.SupportsEpic() {
			epicPaths = append(epicPaths, hiddenPath)
		}
	}
	return epicPaths

}

type fabridCandidate struct {
	path              snet.Path
	hops              []snet.HopInterface
	supportsPolicy    bool
	matchedPolicyIDs  []*fabrid.PolicyID
	fallbackPolicyIDs []*fabrid.PolicyID
	fingerprint       snet.PathFingerprint
}

func newPolicyIDPtr(id fabrid.PolicyID) *fabrid.PolicyID {
	p := id
	return &p
}

func normalizePolicyString(policy string) string {
	trimmed := strings.TrimSpace(policy)
	if trimmed == "" {
		return ""
	}
	return strings.ToUpper(trimmed)
}

func mergeUniquePaths(slices ...[]snet.Path) []snet.Path {
	seen := make(map[snet.PathFingerprint]struct{})
	var merged []snet.Path
	for _, slice := range slices {
		for _, p := range slice {
			if p == nil {
				continue
			}
			fp := snet.Fingerprint(p)
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			merged = append(merged, p)
		}
	}
	return merged
}

func buildFabridCandidates(paths []snet.Path, requiredPolicies []string) []*fabridCandidate {
	requiredSet := make(map[string]struct{})
	for _, policy := range requiredPolicies {
		normalized := normalizePolicyString(policy)
		if normalized != "" {
			requiredSet[normalized] = struct{}{}
		}
	}
	requirementActive := len(requiredSet) > 0

	var candidates []*fabridCandidate
	for _, p := range paths {
		if p == nil {
			continue
		}
		meta := p.Metadata()
		if meta == nil {
			continue
		}
		hops := meta.Hops()
		if len(hops) == 0 {
			continue
		}
		fallbackIDs := make([]*fabrid.PolicyID, len(hops))
		matchedIDs := make([]*fabrid.PolicyID, len(hops))
		hasFabrid := false
		supports := true

		for i, hop := range hops {
			if !hop.FabridEnabled {
				continue
			}
			hasFabrid = true

			if len(hop.Policies) > 0 {
				fallbackIDs[i] = newPolicyIDPtr(hop.Policies[0].Index)
			} else {
				fallbackIDs[i] = newPolicyIDPtr(fabrid.PolicyID(0))
			}

			if !requirementActive {
				continue
			}
			if !supports {
				continue
			}
			hopMatch := false
			for _, pol := range hop.Policies {
				if pol == nil {
					continue
				}
				if _, ok := requiredSet[normalizePolicyString(pol.String())]; ok {
					matchedIDs[i] = newPolicyIDPtr(pol.Index)
					hopMatch = true
					break
				}
			}
			if !hopMatch {
				supports = false
			}
		}
		if !hasFabrid {
			continue
		}
		candidate := &fabridCandidate{
			path:              p,
			hops:              hops,
			supportsPolicy:    supports || !requirementActive,
			fallbackPolicyIDs: fallbackIDs,
			fingerprint:       snet.Fingerprint(p),
		}
		if requirementActive && supports {
			candidate.matchedPolicyIDs = matchedIDs
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func chooseBestFabridCandidate(candidates []*fabridCandidate, requireSupport bool) *fabridCandidate {
	if len(candidates) == 0 {
		return nil
	}
	var filtered []*fabridCandidate
	for _, candidate := range candidates {
		if !requireSupport || candidate.supportsPolicy {
			filtered = append(filtered, candidate)
		}
	}
	if len(filtered) == 0 {
		if requireSupport {
			return chooseBestFabridCandidate(candidates, false)
		}
		return nil
	}
	pathOptions := make([]snet.Path, len(filtered))
	for i, candidate := range filtered {
		pathOptions[i] = candidate.path
	}
	shortestPaths := findShortestPaths(pathOptions)
	var chosenPath snet.Path
	switch len(shortestPaths) {
	case 0:
		chosenPath = filtered[0].path
	case 1:
		chosenPath = shortestPaths[0]
	default:
		chosenPath = findLexicographicLowestIntfIdsPath(shortestPaths)
	}
	targetFingerprint := snet.Fingerprint(chosenPath)
	for _, candidate := range filtered {
		if candidate.fingerprint == targetFingerprint {
			return candidate
		}
	}
	return filtered[0]
}

func test20(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, hiddenPaths []snet.Path, publicPaths []snet.Path) error {

	var _path snet.Path = nil
	var paths []snet.Path = nil
	var send_packet snet.Packet

	hiddenPathsEPIC := findHiddenPathsSupportingEPIC(hiddenPaths)

	// check if paths is not empty, we assume always at least 1 public path available
	if len(hiddenPathsEPIC) == 0 {
		paths = publicPaths
	} else {
		paths = hiddenPathsEPIC
	}

	// if more than one find shortest path, lower number of interfaces
	if len(paths) == 1 {
		_path = paths[0]
	} else {
		shortestPaths := findShortestPaths(paths)
		// if multiples paths have same numebr of interfaces filter lexicographically by interface ID
		if len(shortestPaths) == 1 {
			_path = shortestPaths[0]
		} else {
			_path = findLexicographicLowestIntfIdsPath(shortestPaths)
		}
	}

	payloadBytes := []byte(`{"ID": 20,"Payload": {}}`)

	if len(hiddenPathsEPIC) != 0 {

		// extend dataplane with EPIC dataplane
		epicPath, err := path.NewEPICDataplanePath(_path.Dataplane().(path.SCION), snet.EpicAuths{AuthPHVF: _path.Metadata().EpicAuths.AuthPHVF, AuthLHVF: _path.Metadata().EpicAuths.AuthLHVF})
		if err != nil {
			return serrors.WrapStr("creating EPIC dataplane path", err)
		}
		send_packet = snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   localIAAddr,
					Host: addr.HostIP(srcIP),
				},
				Destination: snet.SCIONAddress{
					IA:   remote.IA,
					Host: addr.HostIP(dstIP),
				},
				Path:    epicPath,
				Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
				// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
			},
		}
	} else {

		send_packet = snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   localIAAddr,
					Host: addr.HostIP(srcIP),
				},
				Destination: snet.SCIONAddress{
					IA:   remote.IA,
					Host: addr.HostIP(dstIP),
				},
				Path:    _path.Dataplane(),
				Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
				// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
				// check that the type assertion is correct and the value is effectively the port where the daemon is listening
			},
		}
	}

	log.Debug("sending over", "path", _path)
	log.Debug("port source in packet", "srcport", sPktConn.LocalAddr().(*net.UDPAddr).Port)
	log.Debug("next hop in the path", "next hop", _path.UnderlayNextHop())

	// send crafted packer with write and listen for replies from teh verifier
	log.Debug("about to write packet", "SCION datagram", send_packet)
	err := sPktConn.WriteTo(&send_packet, _path.UnderlayNextHop())
	if err != nil {
		return serrors.WrapStr("sending scion msg to verifier", err)
	}
	log.Debug("about to read packet")
	receive_packet := snet.Packet{}
	var sender_underlay net.UDPAddr
	err = sPktConn.ReadFrom(&receive_packet, &sender_underlay)
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

	// TODO edit debgu log to printout test execiution result
	log.Debug("Verifier reply UDPPayload", "payload", string(replyPayload))

	return nil

}

// 30-31-32-33 require to satisfy a FABRID policy specified by the verifier

func test30(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, publicPaths []snet.Path) error {
	if daemonConnectorGlobal == nil {
		return serrors.New("daemon connector is not initialized")
	}
	if len(publicPaths) == 0 {
		return serrors.New("no paths available for FABRID connectivity test")
	}

	candidates := buildFabridCandidates(publicPaths, nil)
	selectedCandidate := chooseBestFabridCandidate(candidates, true)
	if selectedCandidate == nil {
		selectedCandidate = chooseBestFabridCandidate(candidates, false)
	}

	selectedPath := publicPaths[0]
	if selectedCandidate != nil {
		selectedPath = selectedCandidate.path
	}
	if selectedPath == nil {
		return serrors.New("unable to select path for FABRID connectivity test")
	}

	var (
		nextHop         = selectedPath.UnderlayNextHop()
		dataplanePath   = selectedPath.Dataplane()
		fabridPath      *path.FABRID
		policyFulfilled bool
	)

	if selectedCandidate != nil {
		scionDataplane, ok := selectedCandidate.path.Dataplane().(path.SCION)
		if !ok {
			log.Debug("Selected path does not expose SCION dataplane for FABRID",
				"type", fmt.Sprintf("%T", selectedCandidate.path.Dataplane()))
		} else {
			fabridCfg := &path.FabridConfig{
				LocalIA:         localIAAddr,
				LocalAddr:       srcIP.String(),
				DestinationIA:   remote.IA,
				DestinationAddr: dstIP.String(),
				ValidationRatio: 128,
			}
			fabridCfg.ValidationHandler = func(ps *fabridcommon.PathState, opt *extension.FabridControlOption, success bool) error {
				if !success {
					log.Info("FABRID validation reported failure", "stats", ps.Stats, "optionType", opt.Type)
				} else {
					log.Debug("FABRID validation succeeded", "stats", ps.Stats)
				}
				return nil
			}
			policiesToUse := selectedCandidate.fallbackPolicyIDs
			fPath, err := path.NewFABRIDDataplanePath(scionDataplane, selectedCandidate.hops, policiesToUse, fabridCfg, daemonConnectorGlobal.FabridKeys)
			if err != nil {
				log.Debug("Failed to build FABRID dataplane path", "err", err)
			} else {
				fabridPath = fPath
				dataplanePath = fPath
				policyFulfilled = true
			}
		}
	}

	testPayload := lib.Test{
		ID:      lib.FabridConnectivityTest,
		Payload: policyFulfilled,
	}
	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		return serrors.WrapStr("encoding FABRID connectivity payload", err)
	}

	finalPacket := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localIAAddr,
				Host: addr.HostIP(srcIP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(dstIP),
			},
			Path:    dataplanePath,
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(sPktConn.LocalAddr().(*net.UDPAddr).Port), Payload: payloadBytes},
		},
	}
	if err := sPktConn.WriteTo(&finalPacket, nextHop); err != nil {
		return serrors.WrapStr("sending FABRID connectivity result", err)
	}

	var response snet.Packet
	var responseUnderlay net.UDPAddr
	if err := sPktConn.ReadFrom(&response, &responseUnderlay); err != nil {
		return serrors.WrapStr("reading FABRID connectivity response", err)
	}

	if fabridPath != nil && response.E2eExtension != nil {
		for _, opt := range response.E2eExtension.Options {
			if opt.OptType != slayers.OptTypeFabridControl {
				continue
			}
			controlOption, err := extension.ParseFabridControlOption(opt)
			if err != nil {
				return serrors.WrapStr("parsing FABRID control option", err)
			}
			if err := fabridPath.HandleFabridControlOption(controlOption, nil); err != nil {
				return serrors.WrapStr("handling FABRID control option", err)
			}
		}
	}

	var finalPayload []byte
	if udpPayload, ok := response.Payload.(snet.UDPPayload); ok {
		finalPayload = udpPayload.Payload
		log.Debug("FABRID verifier reply", "payload", string(finalPayload))
	} else {
		log.Debug("FABRID verifier reply not UDP", "type", fmt.Sprintf("%T", response.Payload))
	}

	if len(finalPayload) > 0 {
		var result lib.TestResult
		if err := json.Unmarshal(finalPayload, &result); err == nil && result.ID == lib.FabridConnectivityTest {
			if result.State == lib.TestFailed {
				return serrors.New("FABRID connectivity test reported failure")
			}
		}
	}

	return nil
}

/*
ALL POSSIBLE POLICIES

- L1000: Route only over routers produced by manufacturer A
- L1001: Route only over routers produced by manufacturer B
- L1002: Route only over routers produced by manufacturer C
- L2000: Route only over routers that support remote attestation
*/

// For this test you have to find a FABRID policy that restricts paths to only route over routers that are either manufactured by manufacturer A or manufacturer B.
func test31(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, publicPaths []snet.Path) error {

}

/*
For this test you have to find a FABRID policy that that restricts paths where all routers in ISD 1 are manufactured by manufacturer A and all routers in ISD 2 are manufactured by manufacturer B or C.
If only one ISD has to be traversed, the policies of the other ISD do not matter.
*/
func test32(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, publicPaths []snet.Path) error {

}

/*
For this test you have to route over routers that support remote attestation. If an intermediate hop does not support remote attestation, you can route over any routers produced by manufacturer C, but the last hop to the destination must support remote attestation
Additionally, do not enforce any policies for the local AS.
*/
func test33(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, publicPaths []snet.Path) error {

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
	daemonConnectorGlobal = daemonConnector
	defer daemonConnector.Close()

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

	// obtain available hidden paths from daemon for the verifier AS
	hiddenPaths, err := daemonConnector.Paths(ctx, remote.IA, localIAAddr, daemon.PathReqFlags{Hidden: true})
	if err != nil {
		return serrors.WrapStr("getting hidden paths from daemon to verifier AS", err)
	}

	log.Debug("received hidden paths from daemon", "total paths", len(hiddenPaths))

	//	log.Debug("first sample", "total paths", len(hiddenPaths))
	// Handle no available paths - terminate execution if no paths found
	if len(pathsToVerIA) == 0 {
		log.Error("No paths available to verifier IA", "verifierIA", remote.IA, "localIA", localIAAddr)
		return serrors.New("no paths available to destination")
	}

	// TODO runtime debugging due to IDE misinterpretation for all paths print type of Bandwidth and Latency values and all their values
	log.Debug("Public Paths to verifier IA", "count", len(pathsToVerIA))
	for i, path := range pathsToVerIA {
		pathMeta := path.Metadata()
		log.Debug("Path", "index", i, "path", pathMeta)
	}
	log.Debug("Hidden Paths to verifier IA", "count", len(pathsToVerIA))
	for i, path := range pathsToVerIA {
		pathMeta := path.Metadata()
		log.Debug("Path", "index", i, "path", pathMeta)
	}

	// 	for j, bw := range pathMeta.Bandwidth {
	// 		log.Debug("Bandwidth entry", "pathIndex", i, "entryIndex", j, "value", bw, "valueType", fmt.Sprintf("%T", bw))
	// 	}
	// 	for j, lat := range pathMeta.Latency {
	// 		log.Debug("Latency entry", "pathIndex", i, "entryIndex", j, "value", int64(lat), "valueType", fmt.Sprintf("%T", lat))
	// 	}
	// 	for j, iface := range pathMeta.Interfaces {
	// 		log.Debug("Interface entry", "pathIndex", i, "entryIndex", j, "id", iface.ID, "idType", fmt.Sprintf("%T", iface.ID), "ia", iface.IA, "iaType", fmt.Sprintf("%T", iface.IA))
	// 	}
	// }

	// TODO runtime debugging due to IDE misinterpretation for all paths print type of Bandwidth and Latency valeus and all their values

	// extend remote, with next hop(this AS border router) and one dataplane path
	// Check if destination is in a remote AS (more than one segment in path indicates crossing AS boundaries)
	// TODO check if needed now with SCIONPacketConn, instead of just SCIONNetwork
	isRemoteAS := len(pathsToVerIA) > 0 && pathsToVerIA[0].Source() != pathsToVerIA[0].Destination()
	if isRemoteAS {
		remote.NextHop = pathsToVerIA[0].UnderlayNextHop()
		remote.Path = pathsToVerIA[0].Dataplane()
		log.Debug("Remote AS detected, setting path and next hop")
	} else {
		log.Debug("Same AS communication, no path extension needed")
	}

	// establish connection with the verifier
	// TODO set ReplyPatcher and SCMPhandler too.
	scionNetwork := &snet.SCIONNetwork{Topology: daemonConnector}
	spktConn, err := scionNetwork.OpenRaw(ctx, localAddr.Host)
	if err != nil {
		return serrors.WrapStr("opening packet connection", err)
	}

	log.Debug("opened raw conection bound to underlay", "local AS border router", spktConn.LocalAddr)

	// type assertion OpenRaw actually returns a SCIONPacketConn, but signed with PacketConn
	// TODO use to set more easiliy write and read buffer
	scionPktConn, ok := spktConn.(*snet.SCIONPacketConn)
	if !ok {
		return serrors.New("failed to cast PacketConn to SCIONPacketConn")
	}

	srcNetIPAddr, err := netip.ParseAddr(localAddr.Host.IP.String())
	if err != nil {
		return serrors.WrapStr("parsing local IP address", err)
	}
	dstNetIPAddr, err := netip.ParseAddr(remote.Host.IP.String())
	if err != nil {
		return serrors.WrapStr("parsing remote IP address", err)
	}

	err = test1(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA[0])
	if err != nil {
		return serrors.WrapStr("failed test 1, due to : ", err)
	}
	err = test2(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 2, due to :s", err)
	}
	err = test10(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 10, due to :s", err)
	}
	err = test11(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 11, due to :s", err)
	}
	err = test20(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, hiddenPaths, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test30(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test31(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test32(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test33(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, pathsToVerIA)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}

	defer scionPktConn.Close()

	return nil
}
