package log

import "fmt"

func LogConnection(protocol, sniSet, domain, srcIP string, srcPort uint16, ipSet, dstIP string, dstPort uint16, srcMac, tlsVersion, metadata string) {
	if IsDiscoveryActive() {
		return
	}
	if metadata != "" {
		Infof(",%s,%s,%s,%s:%d,%s,%s:%d,%s,%s,%s", protocol, sniSet, domain, srcIP, srcPort, ipSet, dstIP, dstPort, srcMac, tlsVersion, metadata)
	} else {
		Infof(",%s,%s,%s,%s:%d,%s,%s:%d,%s,%s", protocol, sniSet, domain, srcIP, srcPort, ipSet, dstIP, dstPort, srcMac, tlsVersion)
	}
}

func LogConnectionStr(protocol, sniSet, domain, source, ipSet, destination, srcMac, tlsVersion, metadata string) {
	if IsDiscoveryActive() {
		return
	}
	if metadata != "" {
		Infof(",%s,%s,%s,%s,%s,%s,%s,%s,%s", protocol, sniSet, domain, source, ipSet, destination, srcMac, tlsVersion, metadata)
	} else {
		Infof(",%s,%s,%s,%s,%s,%s,%s,%s", protocol, sniSet, domain, source, ipSet, destination, srcMac, tlsVersion)
	}
}

func FormatHostPort(ip string, port uint16) string {
	return fmt.Sprintf("%s:%d", ip, port)
}
