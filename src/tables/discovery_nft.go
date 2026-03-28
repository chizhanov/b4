package tables

import (
	"fmt"
	"strings"
)

const discoveryChainNFT = "b4_discovery"

type discoveryNftBackend struct{}

func (b *discoveryNftBackend) name() string    { return backendNFTables }
func (b *discoveryNftBackend) available() bool { return hasBinary("nft") }

func (b *discoveryNftBackend) apply(flowMark uint, injectedMark uint, queueStart int, threads int) error {
	_, _ = run("nft", "add", "chain", "inet", nftTableName, discoveryChainNFT)
	_, _ = run("nft", "flush", "chain", "inet", nftTableName, discoveryChainNFT)

	queueExpr := fmt.Sprintf("queue num %d bypass", queueStart)
	if threads > 1 {
		queueExpr = fmt.Sprintf("queue num %d-%d bypass", queueStart, queueStart+threads-1)
	}

	flowHex := fmt.Sprintf("0x%x", flowMark)
	injectedHex := fmt.Sprintf("0x%x", injectedMark)
	queueTokens := strings.Fields(queueExpr)

	rules := [][]string{
		{"add", "rule", "inet", nftTableName, discoveryChainNFT, "meta", "mark", injectedHex, "accept"},
		{"add", "rule", "inet", nftTableName, discoveryChainNFT, "ct", "mark", flowHex, "meta", "mark", "set", "ct", "mark"},
		{"add", "rule", "inet", nftTableName, discoveryChainNFT, "meta", "mark", flowHex, "ct", "mark", "set", "mark"},
	}
	queueRule := append([]string{"add", "rule", "inet", nftTableName, discoveryChainNFT, "meta", "mark", flowHex}, queueTokens...)
	rules = append(rules, queueRule)

	for _, r := range rules {
		if _, err := run(append([]string{"nft"}, r...)...); err != nil {
			return err
		}
	}

	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "output", "jump", discoveryChainNFT)
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "prerouting", "jump", discoveryChainNFT)

	if _, err := run("nft", "insert", "rule", "inet", nftTableName, "output", "jump", discoveryChainNFT); err != nil {
		return err
	}
	if _, err := run("nft", "insert", "rule", "inet", nftTableName, "output", "meta", "mark", flowHex, "accept"); err != nil {
		return err
	}
	if _, err := run("nft", "insert", "rule", "inet", nftTableName, "output", "meta", "mark", injectedHex, "accept"); err != nil {
		return err
	}
	if _, err := run("nft", "insert", "rule", "inet", nftTableName, "prerouting", "jump", discoveryChainNFT); err != nil {
		return err
	}
	if _, err := run("nft", "insert", "rule", "inet", nftTableName, "prerouting", "meta", "mark", flowHex, "accept"); err != nil {
		return err
	}
	if _, err := run("nft", "insert", "rule", "inet", nftTableName, "prerouting", "meta", "mark", injectedHex, "accept"); err != nil {
		return err
	}
	return nil
}

func (b *discoveryNftBackend) clear(flowMark uint, injectedMark uint) {
	flowHex := fmt.Sprintf("0x%x", flowMark)
	injectedHex := fmt.Sprintf("0x%x", injectedMark)
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "output", "meta", "mark", flowHex, "accept")
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "prerouting", "meta", "mark", flowHex, "accept")
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "output", "meta", "mark", injectedHex, "accept")
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "prerouting", "meta", "mark", injectedHex, "accept")
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "output", "jump", discoveryChainNFT)
	_, _ = run("nft", "delete", "rule", "inet", nftTableName, "prerouting", "jump", discoveryChainNFT)
	_, _ = run("nft", "flush", "chain", "inet", nftTableName, discoveryChainNFT)
	_, _ = run("nft", "delete", "chain", "inet", nftTableName, discoveryChainNFT)
}
