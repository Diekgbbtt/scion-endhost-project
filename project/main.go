package main

// test comment
import (
	"context"
	"encoding/json"
	"errors"
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
var (
	remote                snet.UDPAddr
	daemonConnectorGlobal daemon.Connector
	currentPaths          []snet.Path
	currentHiddenPaths    []snet.Path
)

// The port of your SCION daemon.
const daemonPort = 30255
const defaultRWTimeout = 5 * time.Second

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

func test1(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	var (
		paths []snet.Path
		err   error
	)
	if refreshPaths != nil {
		paths, _, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for test1", err)
		}
	} else {
		paths = getCurrentPaths()
	}

	usablePaths := filterUsablePaths(paths, time.Now())
	if len(usablePaths) == 0 {
		return serrors.New("no usable paths available for test1")
	}
	pathToVer := usablePaths[0]

	// craft SCION datagram payload according to test task
	payloadBytes := []byte(`{"ID": 1,"Payload": {}}`)

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
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
			Path:    pathToVer.Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	nextHop := pathToVer.UnderlayNextHop()
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}

	// send crafted packer with write and listen for replies from teh verifier
	log.Debug("about to write packet", "SCION datagram", send_packet)
	err = sPktConn.WriteTo(&send_packet, nextHop)
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

// check uniqueness and expiry
func filterUsablePaths(paths []snet.Path, now time.Time) []snet.Path {
	seen := make(map[snet.PathFingerprint]struct{})
	var usable []snet.Path
	for _, p := range paths {
		if p == nil {
			continue
		}
		fp := snet.Fingerprint(p)
		if _, ok := seen[fp]; ok {
			continue
		}
		meta := p.Metadata()
		if meta != nil {
			expiry := meta.Expiry
			if !expiry.IsZero() && now.After(expiry) {
				log.Debug("Skipping expired path", "expiry", expiry)
				continue
			}
		}
		seen[fp] = struct{}{}
		usable = append(usable, p)
	}
	return usable
}

func parseAdditionalPacketCount(payload any) (int, error) {
	switch v := payload.(type) {
	case nil:
		return 0, nil
	case float64:
		return int(v), nil
	case float32:
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case uint:
		return int(v), nil
	case uint64:
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, err
		}
		return int(n), nil
	case map[string]any:
		// allow payloads shaped like {"Remaining": <n>}
		if remaining, ok := v["Remaining"]; ok {
			return parseAdditionalPacketCount(remaining)
		}
	}
	return 0, serrors.New("unexpected payload type for multipath test", "payload", payload)
}

var errPathExpired = serrors.New("path expired")
var errNoUsablePaths = errors.New("no usable paths available")

func ensureNextHopFamily(local *net.UDPAddr, nextHop *net.UDPAddr) error {
	if nextHop == nil {
		return nil
	}
	addrPort, err := netip.ParseAddrPort(nextHop.String())
	if err != nil {
		log.Debug("Failed to parse next hop address", "nextHop", nextHop.String(), "err", err)
		return serrors.WrapStr("parsing next hop address", err)
	}
	localIsV4 := local.IP.To4() != nil
	remoteIsV4 := addrPort.Addr().Is4()
	if localIsV4 != remoteIsV4 {
		log.Debug("Underlay address family mismatch; continuing anyway",
			"localAddr", local.IP.String(), "nextHop", addrPort.String())
	}
	return nil
}

func setCurrentPaths(paths []snet.Path) {
	currentPaths = clonePaths(paths)
}

func setCurrentHiddenPaths(paths []snet.Path) {
	currentHiddenPaths = clonePaths(paths)
}

func getCurrentPaths() []snet.Path {
	return clonePaths(currentPaths)
}

func getCurrentHiddenPaths() []snet.Path {
	return clonePaths(currentHiddenPaths)
}

func clonePaths(src []snet.Path) []snet.Path {
	if len(src) == 0 {
		return nil
	}
	dst := make([]snet.Path, len(src))
	copy(dst, src)
	return dst
}

func test2(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	// craft SCION datagram payload according to test task
	payloadBytes := []byte(`{"ID": 2,"Payload": {}}`)

	buildPathPool := func(paths []snet.Path) ([]snet.Path, error) {
		usable := filterUsablePaths(paths, time.Now())
		if len(usable) == 0 {
			return nil, errNoUsablePaths
		}
		return usable, nil
	}

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}
	localPort := uint16(localUDPAddr.Port)

	paths, _, err := func() ([]snet.Path, []snet.Path, error) {
		if refreshPaths != nil {
			return refreshPaths()
		}
		return getCurrentPaths(), getCurrentHiddenPaths(), nil
	}()
	if err != nil {
		return serrors.WrapStr("refreshing paths for multipath test", err)
	}
	setCurrentPaths(paths)

	var usablePaths []snet.Path
	nextPathIndex := 0

	setPaths := func(paths []snet.Path) error {
		pool, err := buildPathPool(paths)
		if err != nil {
			return err
		}
		setCurrentPaths(paths)
		usablePaths = pool
		nextPathIndex = 0
		return nil
	}

	if err := setPaths(paths); err != nil {
		return serrors.WrapStr("no usable paths available for multipath test", err)
	}

	refreshed := false
	tryRefresh := func(reason string) error {
		if refreshed {
			return serrors.WrapStr("path refresh already attempted", errNoUsablePaths, "reason", reason)
		}
		if refreshPaths == nil {
			return serrors.WrapStr("refresh unavailable", errNoUsablePaths, "reason", reason)
		}
		refreshed = true
		log.Debug("Refreshing paths", "reason", reason)
		refreshedPaths, _, err := refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths", err, "reason", reason)
		}
		if err := setPaths(refreshedPaths); err != nil {
			return serrors.WrapStr("setting refreshed paths", err, "reason", reason)
		}
		return nil
	}

	sendOnPath := func(p snet.Path) error {
		if p == nil {
			return serrors.New("attempted to send on nil path")
		}
		meta := p.Metadata()
		if meta != nil {
			expiry := meta.Expiry
			if !expiry.IsZero() && !time.Now().Before(expiry) {
				log.Debug("Skipping expired path", "expiry", expiry)
				return errPathExpired
			}
		}
		packet := snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   localIAAddr,
					Host: addr.HostIP(srcIP),
				},
				Destination: snet.SCIONAddress{
					IA:   remote.IA,
					Host: addr.HostIP(dstIP),
				},
				Path: p.Dataplane(),
				Payload: snet.UDPPayload{
					DstPort: uint16(remote.Host.Port),
					SrcPort: localPort,
					Payload: payloadBytes,
				},
			},
		}
		nextHop := p.UnderlayNextHop()
		if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
			return err
		}
		return sPktConn.WriteTo(&packet, nextHop)
	}

	sendNextPath := func(reason string) error {
		for {
			if nextPathIndex >= len(usablePaths) {
				if err := tryRefresh(reason); err != nil {
					return err
				}
				continue
			}
			err := sendOnPath(usablePaths[nextPathIndex])
			nextPathIndex++
			if err == nil {
				return nil
			}
			if errors.Is(err, errPathExpired) {
				continue
			}
			if refreshErr := tryRefresh("send failure"); refreshErr == nil {
				continue
			}
			return err
		}
	}

	readResult := func() (lib.TestResult, error) {
		var receivePacket snet.Packet
		var senderUnderlay net.UDPAddr
		if err := sPktConn.ReadFrom(&receivePacket, &senderUnderlay); err != nil {
			return lib.TestResult{}, serrors.WrapStr("reading message from connection", err)
		}

		udpPayload, ok := receivePacket.Payload.(snet.UDPPayload)
		if !ok {
			return lib.TestResult{}, serrors.New("received non-UDP payload from verifier", "payload_type", fmt.Sprintf("%T", receivePacket.Payload))
		}
		log.Debug("Parsed reply payload", "payload", string(udpPayload.Payload))

		var result lib.TestResult
		if err := json.Unmarshal(udpPayload.Payload, &result); err != nil {
			return lib.TestResult{}, serrors.WrapStr("failed to decode verifier reply", err)
		}
		return result, nil
	}

	var result lib.TestResult
	for {
		if err := sendNextPath("initial path pool exhausted"); err != nil {
			return serrors.WrapStr("sending initial SCION packet to verifier", err)
		}
		r, err := readResult()
		if err != nil {
			if refreshErr := tryRefresh("initial read failure"); refreshErr == nil {
				continue
			}
			return err
		}
		result = r
		break
	}

	testStatus := result.State
	requiredAddpackets, err := parseAdditionalPacketCount(result.Payload)
	if err != nil {
		return serrors.WrapStr("parsing required additional packets", err)
	}

	log.Debug("Initial test status", "status", testStatus, "requiredAddpackets", requiredAddpackets)

	// loop while (testStatus == lib.TestState.TestRunning)
	for testStatus == lib.TestRunning {
		log.Debug("Sending additional packet", "remaining_packets", requiredAddpackets)

		if err := sendNextPath("multipath pool exhausted"); err != nil {
			return serrors.WrapStr("sending additional SCION packet to verifier", err)
		}

		r, err := readResult()
		if err != nil {
			if refreshErr := tryRefresh("read failure during multipath"); refreshErr == nil {
				continue
			}
			return err
		}
		result = r

		testStatus = result.State
		requiredAddpackets, err = parseAdditionalPacketCount(result.Payload)
		if err != nil {
			return serrors.WrapStr("parsing required additional packets in loop", err)
		}

		log.Debug("Updated test status", "status", testStatus, "requiredAddpackets", requiredAddpackets)
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
func test10(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	var (
		paths []snet.Path
		err   error
	)
	if refreshPaths != nil {
		paths, _, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for test10", err)
		}
	} else {
		paths = getCurrentPaths()
	}

	usablePaths := filterUsablePaths(paths, time.Now())
	if len(usablePaths) == 0 {
		return serrors.New("no usable paths available for test10")
	}

	foundLeastCarbonIntensitypath := false
	var path snet.Path
	i := 0
	for !foundLeastCarbonIntensitypath {
		foundLeastCarbonIntensitypath, path = findLeastCarbonIntensityPath(usablePaths, i)
		i++
	}

	payloadBytes := []byte(`{"ID": 10,"Payload": {}}`)

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
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
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	nextHop := path.UnderlayNextHop()
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}

	// send crafted packer with write and listen for replies from teh verifier
	err = sPktConn.WriteTo(&send_packet, nextHop)
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

// TODO change higher bandwidth finding handling this edge case If none of the links of a path have bandwidth configured then it is treated as infinite bandwidth in this Test.
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

func test11(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	var (
		paths []snet.Path
		err   error
	)
	if refreshPaths != nil {
		paths, _, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for test11", err)
		}
	} else {
		paths = getCurrentPaths()
	}

	usablePaths := filterUsablePaths(paths, time.Now())
	if len(usablePaths) == 0 {
		return serrors.New("no usable paths available for test11")
	}

	// send simple packet with testid 11
	// parse latencyBound with UDPPayload payload of reply

	payloadBytes := []byte(`{"ID": 11,"Payload": {}}`)

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}

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
			Path:    usablePaths[0].Dataplane(), // path retrieved from daemon
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	nextHop := usablePaths[0].UnderlayNextHop()
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}

	// send crafted packer with write and listen for replies from teh verifier
	err = sPktConn.WriteTo(&send_sample_packet, nextHop)
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
	for _, _path := range usablePaths {
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
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
			// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
		},
	}

	nextHop = path.UnderlayNextHop()
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}

	// send crafted packer with write and listen for replies from teh verifier
	err = sPktConn.WriteTo(&send_packet, nextHop)
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

// buildFabridCandidatesTest32 evaluates paths for the manufacturer-per-ISD policy used in test32.
// A path complies if every hop that resides in ISD 1 advertises policy L1000 (manufacturer A)
// and every hop in ISD 2 advertises either L1001 or L1002 (manufacturers B or C). Paths that
// do not traverse one of the targeted ISDs are still considered valid as long as the traversed
// ISDs satisfy their respective constraints. The function returns candidates annotated with the
// hop-by-hop policy choices that a FABRID dataplane path should enforce.
func buildFabridCandidatesTest32(paths []snet.Path) []*fabridCandidate {
	type policySet []string
	requiredByISD := map[addr.ISD]policySet{
		addr.ISD(1): {"L1000"},
		addr.ISD(2): {"L1001", "L1002"},
	}

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
			if hop.FabridEnabled {
				hasFabrid = true
			}
			if len(hop.Policies) > 0 {
				fallbackIDs[i] = newPolicyIDPtr(hop.Policies[0].Index)
			}

			required := requiredByISD[hop.IA.ISD()]
			if len(required) == 0 {
				continue
			}
			if !hop.FabridEnabled {
				supports = false
				continue
			}

			matched := false
			for _, pol := range hop.Policies {
				if pol == nil {
					continue
				}
				name := normalizePolicyString(pol.String())
				for _, need := range required {
					if name == need {
						matchedIDs[i] = newPolicyIDPtr(pol.Index)
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				supports = false
			}
		}
		if !hasFabrid {
			continue
		}
		candidate := &fabridCandidate{
			path:              p,
			hops:              hops,
			supportsPolicy:    supports,
			matchedPolicyIDs:  matchedIDs,
			fallbackPolicyIDs: fallbackIDs,
			fingerprint:       snet.Fingerprint(p),
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

// buildFabridCandidatesTest33 enforces per-hop requirements for the remote attestation policy:
//   - local AS hops remain unchecked;
//   - every intermediate hop must expose L2000 (remote attestation) when possible, otherwise fall back to L1002 (manufacturer C);
//   - the last hop towards the destination must advertise L2000 (fallback to L1002 is not acceptable).
//
// Intermediate hops that only offer manufacturer C remain compliant (the topology explicitly allows this),
// they are therefore marked as supported. Only when no acceptable policy is available is supportsPolicy set to false.
func buildFabridCandidatesTest33(paths []snet.Path, localIA, destIA addr.IA) []*fabridCandidate {
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
			if hop.FabridEnabled {
				hasFabrid = true
			}
			if len(hop.Policies) > 0 {
				fallbackIDs[i] = newPolicyIDPtr(hop.Policies[0].Index)
			}

			// Skip policy enforcement for the local AS hop entirely.
			if hop.IA == localIA {
				continue
			}

			isLastHop := i == len(hops)-1
			requireRemoteAttestation := isLastHop || hop.IA == destIA
			var remotePolicy *fabrid.PolicyID
			var manufacturerCPolicy *fabrid.PolicyID

			for _, pol := range hop.Policies {
				if pol == nil {
					continue
				}
				switch normalizePolicyString(pol.String()) {
				case "L2000":
					remotePolicy = newPolicyIDPtr(pol.Index)
				case "L1002":
					manufacturerCPolicy = newPolicyIDPtr(pol.Index)
				}
			}

			switch {
			case remotePolicy != nil:
				matchedIDs[i] = remotePolicy
			case !requireRemoteAttestation && manufacturerCPolicy != nil:
				matchedIDs[i] = manufacturerCPolicy
			default:
				supports = false
			}
		}

		if !hasFabrid {
			continue
		}
		candidate := &fabridCandidate{
			path:              p,
			hops:              hops,
			supportsPolicy:    supports,
			matchedPolicyIDs:  matchedIDs,
			fallbackPolicyIDs: fallbackIDs,
			fingerprint:       snet.Fingerprint(p),
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

func test20(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	var (
		allPaths    []snet.Path
		hiddenPaths []snet.Path
		err         error
	)
	if refreshPaths != nil {
		allPaths, hiddenPaths, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for test20", err)
		}
	} else {
		allPaths = getCurrentPaths()
		hiddenPaths = getCurrentHiddenPaths()
	}

	allUsable := filterUsablePaths(allPaths, time.Now())
	hiddenUsable := filterUsablePaths(hiddenPaths, time.Now())
	hiddenPathsEPIC := findHiddenPathsSupportingEPIC(hiddenUsable)

	var paths []snet.Path
	switch {
	case len(hiddenPathsEPIC) > 0:
		paths = hiddenPathsEPIC
	case len(allUsable) > 0:
		paths = allUsable
	default:
		return serrors.New("no usable paths available for test20")
	}

	var _path snet.Path
	var send_packet snet.Packet

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

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}

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
				Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
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
				Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
				// spktConn.OpenRaw() opens a socket listening on the specified address, though the dispatcher(daemon) opens a random port
				// check that the type assertion is correct and the value is effectively the port where the daemon is listening
			},
		}
	}

	log.Debug("sending over", "path", _path)
	log.Debug("port source in packet", "srcport", localUDPAddr.Port)
	nextHop := _path.UnderlayNextHop()
	log.Debug("next hop in the path", "next hop", nextHop)
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}

	// send crafted packer with write and listen for replies from teh verifier
	log.Debug("about to write packet", "SCION datagram", send_packet)
	err = sPktConn.WriteTo(&send_packet, nextHop)
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

func test30(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA, refreshPaths func() ([]snet.Path, []snet.Path, error)) error {
	if daemonConnectorGlobal == nil {
		return serrors.New("daemon connector is not initialized")
	}
	var (
		paths []snet.Path
		err   error
	)
	if refreshPaths != nil {
		paths, _, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for FABRID connectivity test", err)
		}
	} else {
		paths = getCurrentPaths()
	}
	usablePaths := filterUsablePaths(paths, time.Now())
	if len(usablePaths) == 0 {
		return serrors.New("no paths available for FABRID connectivity test")
	}

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}

	candidates := buildFabridCandidates(usablePaths, nil)
	selectedCandidate := chooseBestFabridCandidate(candidates, true)
	if selectedCandidate == nil {
		selectedCandidate = chooseBestFabridCandidate(candidates, false)
	}

	selectedPath := usablePaths[0]
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
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
		},
	}
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
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
func test31(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA,
	refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	if daemonConnectorGlobal == nil {
		return serrors.New("daemon connector is not initialized")
	}

	var (
		paths  []snet.Path
		hidden []snet.Path
		err    error
	)
	if refreshPaths != nil {
		paths, hidden, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for FABRID manufacturer policy test", err)
		}
	} else {
		paths = getCurrentPaths()
		hidden = getCurrentHiddenPaths()
	}

	usablePaths := filterUsablePaths(paths, time.Now())
	usableHidden := filterUsablePaths(hidden, time.Now())
	if len(usablePaths) == 0 && len(usableHidden) == 0 {
		return serrors.New("no paths available for FABRID manufacturer policy test")
	}

	allPaths := mergeUniquePaths(usablePaths, usableHidden)
	requiredPolicies := []string{"L1000", "L1001"}
	candidates := buildFabridCandidates(allPaths, requiredPolicies)
	supportedCandidate := chooseBestFabridCandidate(candidates, true)
	fallbackCandidate := supportedCandidate
	if fallbackCandidate == nil {
		fallbackCandidate = chooseBestFabridCandidate(candidates, false)
	}

	selectedPath := allPaths[0]
	if fallbackCandidate != nil {
		selectedPath = fallbackCandidate.path
	}
	if selectedPath == nil {
		return serrors.New("unable to select path for FABRID manufacturer policy test")
	}

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}

	nextHop := selectedPath.UnderlayNextHop()
	dataplanePath := selectedPath.Dataplane()

	policyFulfilled := supportedCandidate != nil
	candidateToUse := fallbackCandidate

	var fabridPath *path.FABRID
	if candidateToUse != nil {
		scionDataplane, ok := candidateToUse.path.Dataplane().(path.SCION)
		if !ok {
			log.Debug("FABRID manufacturer path is not SCION", "type", fmt.Sprintf("%T", candidateToUse.path.Dataplane()))
			policyFulfilled = false
		} else {
			policiesToUse := candidateToUse.fallbackPolicyIDs
			if supportedCandidate != nil && len(candidateToUse.matchedPolicyIDs) > 0 {
				policiesToUse = candidateToUse.matchedPolicyIDs
			}
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
			p, err := path.NewFABRIDDataplanePath(scionDataplane, candidateToUse.hops, policiesToUse,
				fabridCfg, daemonConnectorGlobal.FabridKeys)
			if err != nil {
				log.Debug("Failed to build FABRID dataplane path for manufacturer policy", "err", err)
				policyFulfilled = false
			} else {
				fabridPath = p
				dataplanePath = p
			}
		}
	} else {
		policyFulfilled = false
	}

	testPayload := lib.Test{
		ID:      lib.FabridPolicy1Test,
		Payload: policyFulfilled,
	}
	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		return serrors.WrapStr("encoding FABRID manufacturer policy payload", err)
	}

	sendPacket := snet.Packet{
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
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
		},
	}
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}
	if err := sPktConn.WriteTo(&sendPacket, nextHop); err != nil {
		return serrors.WrapStr("sending FABRID manufacturer policy result", err)
	}

	var response snet.Packet
	var responseUnderlay net.UDPAddr
	if err := sPktConn.ReadFrom(&response, &responseUnderlay); err != nil {
		return serrors.WrapStr("reading FABRID manufacturer policy response", err)
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

	if udpPayload, ok := response.Payload.(snet.UDPPayload); ok {
		log.Debug("FABRID manufacturer policy verifier reply", "payload", string(udpPayload.Payload))
	} else {
		log.Debug("FABRID manufacturer policy verifier reply not UDP", "type", fmt.Sprintf("%T", response.Payload))
	}

	return nil
}

/*
For this test you have to find a FABRID policy that that restricts paths where all routers in ISD 1 are manufactured by manufacturer A and all routers in ISD 2 are manufactured by manufacturer B or C.
If only one ISD has to be traversed, the policies of the other ISD do not matter.
*/
func test32(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA,
	refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	if daemonConnectorGlobal == nil {
		return serrors.New("daemon connector is not initialized")
	}

	var (
		paths  []snet.Path
		hidden []snet.Path
		err    error
	)
	if refreshPaths != nil {
		paths, hidden, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for FABRID dual-isd policy test", err)
		}
	} else {
		paths = getCurrentPaths()
		hidden = getCurrentHiddenPaths()
	}

	usablePaths := filterUsablePaths(paths, time.Now())
	usableHidden := filterUsablePaths(hidden, time.Now())
	if len(usablePaths) == 0 && len(usableHidden) == 0 {
		return serrors.New("no paths available for FABRID dual-isd policy test")
	}

	allPaths := mergeUniquePaths(usablePaths, usableHidden)

	// buildFabridCandidatesTest32 validates manufacturer policies per ISD and annotates the hops
	// with the exact FABRID policy IDs that should be enforced.
	candidates := buildFabridCandidatesTest32(allPaths)
	supportedCandidate := chooseBestFabridCandidate(candidates, true)
	fallbackCandidate := supportedCandidate
	if fallbackCandidate == nil {
		fallbackCandidate = chooseBestFabridCandidate(candidates, false)
	}

	selectedPath := allPaths[0]
	if fallbackCandidate != nil {
		selectedPath = fallbackCandidate.path
	}
	if selectedPath == nil {
		return serrors.New("unable to select path for FABRID dual-isd policy test")
	}

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}

	nextHop := selectedPath.UnderlayNextHop()
	dataplanePath := selectedPath.Dataplane()

	policyFulfilled := supportedCandidate != nil
	candidateToUse := fallbackCandidate

	var fabridPath *path.FABRID
	if candidateToUse != nil {
		scionDataplane, ok := candidateToUse.path.Dataplane().(path.SCION)
		if !ok {
			log.Debug("FABRID dual-isd path is not SCION", "type", fmt.Sprintf("%T", candidateToUse.path.Dataplane()))
			policyFulfilled = false
		} else {
			policiesToUse := candidateToUse.fallbackPolicyIDs
			if supportedCandidate != nil && len(candidateToUse.matchedPolicyIDs) > 0 {
				policiesToUse = candidateToUse.matchedPolicyIDs
			}
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
			p, err := path.NewFABRIDDataplanePath(scionDataplane, candidateToUse.hops, policiesToUse,
				fabridCfg, daemonConnectorGlobal.FabridKeys)
			if err != nil {
				log.Debug("Failed to build FABRID dataplane path for dual-isd policy", "err", err)
				policyFulfilled = false
			} else {
				fabridPath = p
				dataplanePath = p
			}
		}
	} else {
		policyFulfilled = false
	}

	testPayload := lib.Test{
		ID:      lib.FabridPolicy2Test,
		Payload: policyFulfilled,
	}
	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		return serrors.WrapStr("encoding FABRID dual-isd policy payload", err)
	}

	sendPacket := snet.Packet{
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
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
		},
	}
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}
	if err := sPktConn.WriteTo(&sendPacket, nextHop); err != nil {
		return serrors.WrapStr("sending FABRID dual-isd policy result", err)
	}

	var response snet.Packet
	var responseUnderlay net.UDPAddr
	if err := sPktConn.ReadFrom(&response, &responseUnderlay); err != nil {
		return serrors.WrapStr("reading FABRID dual-isd policy response", err)
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

	if udpPayload, ok := response.Payload.(snet.UDPPayload); ok {
		log.Debug("FABRID dual-isd policy verifier reply", "payload", string(udpPayload.Payload))
	} else {
		log.Debug("FABRID dual-isd policy verifier reply not UDP", "type", fmt.Sprintf("%T", response.Payload))
	}

	return nil
}

/*
For this test you have to route over routers that support remote attestation. If an intermediate hop does not support remote attestation, you can route over any routers produced by manufacturer C, but the last hop to the destination must support remote attestation
Additionally, do not enforce any policies for the local AS.
For each hop (except the special case about local AS and destination AS) it should try to enforce remote attestation, if that particular hop does not support it, enforce produced by manufacturer C for that hop. The last hop to the destination must support remote attestation and for the local AS you don't have to enforce any policy.
*/
func test33(sPktConn snet.PacketConn, srcIP netip.Addr, dstIP netip.Addr, localIAAddr addr.IA,
	refreshPaths func() ([]snet.Path, []snet.Path, error)) error {

	if daemonConnectorGlobal == nil {
		return serrors.New("daemon connector is not initialized")
	}

	var (
		paths  []snet.Path
		hidden []snet.Path
		err    error
	)
	if refreshPaths != nil {
		paths, hidden, err = refreshPaths()
		if err != nil {
			return serrors.WrapStr("refreshing paths for FABRID attestation policy test", err)
		}
	} else {
		paths = getCurrentPaths()
		hidden = getCurrentHiddenPaths()
	}

	usablePaths := filterUsablePaths(paths, time.Now())
	usableHidden := filterUsablePaths(hidden, time.Now())
	if len(usablePaths) == 0 && len(usableHidden) == 0 {
		return serrors.New("no paths available for FABRID attestation policy test")
	}

	allPaths := mergeUniquePaths(usablePaths, usableHidden)
	candidates := buildFabridCandidatesTest33(allPaths, localIAAddr, remote.IA)
	supportedCandidate := chooseBestFabridCandidate(candidates, true)
	fallbackCandidate := supportedCandidate
	if fallbackCandidate == nil {
		fallbackCandidate = chooseBestFabridCandidate(candidates, false)
	}

	selectedPath := allPaths[0]
	if fallbackCandidate != nil {
		selectedPath = fallbackCandidate.path
	}
	if selectedPath == nil {
		return serrors.New("unable to select path for FABRID attestation policy test")
	}

	localUDPAddr, ok := sPktConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return serrors.New("unexpected local address type", "addr", sPktConn.LocalAddr())
	}

	nextHop := selectedPath.UnderlayNextHop()
	dataplanePath := selectedPath.Dataplane()

	policyFulfilled := supportedCandidate != nil
	candidateToUse := fallbackCandidate

	var fabridPath *path.FABRID
	if candidateToUse != nil {
		scionDataplane, ok := candidateToUse.path.Dataplane().(path.SCION)
		if !ok {
			log.Debug("FABRID attestation path is not SCION", "type", fmt.Sprintf("%T", candidateToUse.path.Dataplane()))
			policyFulfilled = false
		} else {
			policiesToUse := candidateToUse.fallbackPolicyIDs
			for _, id := range candidateToUse.matchedPolicyIDs {
				if id != nil {
					policiesToUse = candidateToUse.matchedPolicyIDs
					break
				}
			}
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
			p, err := path.NewFABRIDDataplanePath(scionDataplane, candidateToUse.hops, policiesToUse,
				fabridCfg, daemonConnectorGlobal.FabridKeys)
			if err != nil {
				log.Debug("Failed to build FABRID dataplane path for attestation policy", "err", err)
				policyFulfilled = false
			} else {
				fabridPath = p
				dataplanePath = p
			}
		}
	} else {
		policyFulfilled = false
	}

	testPayload := lib.Test{
		ID:      lib.FabridPolicy3Test,
		Payload: policyFulfilled,
	}
	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		return serrors.WrapStr("encoding FABRID attestation policy payload", err)
	}

	sendPacket := snet.Packet{
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
			Payload: snet.UDPPayload{DstPort: uint16(remote.Host.Port), SrcPort: uint16(localUDPAddr.Port), Payload: payloadBytes},
		},
	}
	if err := ensureNextHopFamily(localUDPAddr, nextHop); err != nil {
		return err
	}
	if err := sPktConn.WriteTo(&sendPacket, nextHop); err != nil {
		return serrors.WrapStr("sending FABRID attestation policy result", err)
	}

	var response snet.Packet
	var responseUnderlay net.UDPAddr
	if err := sPktConn.ReadFrom(&response, &responseUnderlay); err != nil {
		return serrors.WrapStr("reading FABRID attestation policy response", err)
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

	if udpPayload, ok := response.Payload.(snet.UDPPayload); ok {
		log.Debug("FABRID attestation policy verifier reply", "payload", string(udpPayload.Payload))
	} else {
		log.Debug("FABRID attestation policy verifier reply not UDP", "type", fmt.Sprintf("%T", response.Payload))
	}

	return nil
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
	localIAAddr, err := daemonConnectorGlobal.LocalIA(ctx)
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

	pathsToVerIA, err := daemonConnectorGlobal.Paths(ctx, remote.IA, localIAAddr, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		return serrors.WrapStr("getting paths to verifier IA", err)
	}

	// obtain available hidden paths from daemon for the verifier AS
	hiddenPaths, err := daemonConnectorGlobal.Paths(ctx, remote.IA, localIAAddr, daemon.PathReqFlags{Hidden: true})
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
	log.Debug("Hidden Paths to verifier IA", "count", len(hiddenPaths))
	for i, path := range hiddenPaths {
		pathMeta := path.Metadata()
		log.Debug("Path", "index", i, "path", pathMeta)
	}

	uniquePaths := mergeUniquePaths(pathsToVerIA, hiddenPaths)
	if len(uniquePaths) == 0 {
		return serrors.New("no unique paths available to verifier IA")
	}
	setCurrentPaths(uniquePaths)
	setCurrentHiddenPaths(hiddenPaths)

	refreshAllPaths := func() ([]snet.Path, []snet.Path, error) {
		refreshedPublic, err := daemonConnectorGlobal.Paths(ctx, remote.IA, localIAAddr, daemon.PathReqFlags{Refresh: true})
		if err != nil {
			return nil, nil, err
		}
		refreshedHidden, err := daemonConnectorGlobal.Paths(ctx, remote.IA, localIAAddr, daemon.PathReqFlags{Hidden: true, Refresh: true})
		if err != nil {
			return nil, nil, err
		}
		merged := mergeUniquePaths(refreshedPublic, refreshedHidden)
		setCurrentPaths(merged)
		setCurrentHiddenPaths(refreshedHidden)
		return merged, refreshedHidden, nil
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
		// remote.NextHop = pathsToVerIA[0].UnderlayNextHop()
		// remote.Path = pathsToVerIA[0].Dataplane()
		log.Debug("Remote AS detected, setting path and next hop")
	} else {
		log.Debug("Same AS communication, no path extension needed")
	}

	// establish connection with the verifier
	scionNetwork := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: daemonConnectorGlobal},
		},
		Topology: daemonConnectorGlobal,
	}

	spktConn, err := scionNetwork.OpenRaw(ctx, localAddr.Host)
	if err != nil {
		return serrors.WrapStr("opening packet connection", err)
	}
	if err := spktConn.SetReadDeadline(time.Now().Add(defaultRWTimeout)); err != nil {
		return serrors.WrapStr("setting read deadline", err)
	}
	if err := spktConn.SetWriteDeadline(time.Now().Add(defaultRWTimeout)); err != nil {
		return serrors.WrapStr("setting write deadline", err)
	}
	defer spktConn.Close()

	log.Debug("opened raw conection bound to underlay", "local AS border router", spktConn.LocalAddr)

	// type assertion OpenRaw actually returns a SCIONPacketConn, but signed with PacketConn
	// TODO use to set more easiliy write and read buffer
	scionPktConn, ok := spktConn.(*snet.SCIONPacketConn)
	if !ok {
		return serrors.New("failed to cast PacketConn to SCIONPacketConn")
	}
	defer scionPktConn.Close()

	srcNetIPAddr, err := netip.ParseAddr(localAddr.Host.IP.String())
	if err != nil {
		return serrors.WrapStr("parsing local IP address", err)
	}
	dstNetIPAddr, err := netip.ParseAddr(remote.Host.IP.String())
	if err != nil {
		return serrors.WrapStr("parsing remote IP address", err)
	}

	err = test1(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 1, due to : ", err)
	}
	err = test2(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 2, due to :s", err)
	}
	err = test10(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 10, due to :s", err)
	}
	err = test11(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 11, due to :s", err)
	}
	err = test20(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test30(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test31(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test32(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}
	err = test33(spktConn, srcNetIPAddr, dstNetIPAddr, localIAAddr, refreshAllPaths)
	if err != nil {
		return serrors.WrapStr("failed test 20, due to :s", err)
	}

	return nil
}
