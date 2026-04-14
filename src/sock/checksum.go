package sock

import "encoding/binary"

const (
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58
)

func FixIPv4L4Checksum(packet []byte, ihl int, proto uint8) {
	FixIPv4Checksum(packet[:ihl])

	switch proto {
	case ipProtoTCP:
		FixTCPChecksum(packet)
	case ipProtoUDP:
		FixUDPChecksum(packet, ihl)
	case ipProtoICMP:
		FixICMPChecksumV4(packet, ihl)
	}
}

func FixIPv6L4Checksum(packet []byte, l4Off int, proto uint8) {
	if len(packet) < 40 || l4Off < 40 || l4Off > len(packet) {
		return
	}

	l4 := packet[l4Off:]
	if len(l4) == 0 {
		return
	}

	var csumOff int
	switch proto {
	case ipProtoTCP:
		if len(l4) < 20 {
			return
		}
		csumOff = 16
	case ipProtoUDP:
		if len(l4) < 8 {
			return
		}
		csumOff = 6
	case ipProtoICMPv6:
		if len(l4) < 8 {
			return
		}
		csumOff = 2
	default:
		return
	}

	l4[csumOff], l4[csumOff+1] = 0, 0

	sum := uint32(0)
	sum = checksumAcc(sum, packet[8:24])
	sum = checksumAcc(sum, packet[24:40])

	plen := make([]byte, 4)
	binary.BigEndian.PutUint32(plen, uint32(len(l4)))
	sum = checksumAcc(sum, plen)
	sum += uint32(proto)
	sum = checksumAcc(sum, l4)

	cs := checksumFold(sum)
	if proto == ipProtoUDP && cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(l4[csumOff:csumOff+2], cs)
}

func FixICMPChecksumV4(packet []byte, ihl int) {
	if len(packet) < ihl+8 {
		return
	}
	icmp := packet[ihl:]
	icmp[2], icmp[3] = 0, 0
	cs := checksum16(icmp)
	binary.BigEndian.PutUint16(icmp[2:4], cs)
}

func checksum16(b []byte) uint16 {
	return checksumFold(checksumAcc(0, b))
}

func checksumAcc(sum uint32, b []byte) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
