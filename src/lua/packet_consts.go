package lua

const (
	IPv4             = 4
	IPv6             = 6
	IPv4HeaderMinLen = 20
	IPv6HeaderLen    = 40
	TCPHeaderMinLen  = 20
	UDPHeaderLen     = 8

	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoIPIP   = 4
	ipProtoIPv6   = 41
	ipProtoICMPv6 = 58
	ipProtoNone   = 59

	ipProtoHopByHop = 0
	ipProtoRouting  = 43
	ipProtoFragment = 44
	ipProtoAH       = 51
	ipProtoDestOpts = 60
)
