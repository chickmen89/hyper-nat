package nat

import (
	"net"

	"github.com/igjeong/hyper-nat/config"
)

// RuleMatcher handles rule matching for NAT decisions.
type RuleMatcher struct {
	rules        []config.Rule
	defaultNATIP net.IP // Default NAT IP from config
}

// NewRuleMatcher creates a new rule matcher from configuration.
func NewRuleMatcher(cfg *config.Config) *RuleMatcher {
	return &RuleMatcher{
		rules:        cfg.Rules,
		defaultNATIP: cfg.NATIP,
	}
}

// MatchResult represents the result of rule matching.
type MatchResult struct {
	RuleName string
	Action   config.Action
	NATIP    net.IP // NAT IP to use (rule-specific or default)
	Matched  bool
}

// Match finds the first matching rule for the given destination IP.
// Rules are evaluated in order; first match wins.
func (m *RuleMatcher) Match(destIP net.IP) MatchResult {
	for _, rule := range m.rules {
		if rule.Destination.Contains(destIP) {
			natIP := rule.NATIP
			if natIP == nil {
				natIP = m.defaultNATIP // Use default if rule doesn't specify
			}
			return MatchResult{
				RuleName: rule.Name,
				Action:   rule.Action,
				NATIP:    natIP,
				Matched:  true,
			}
		}
	}

	// No rule matched - default to bypass (fail-safe)
	return MatchResult{
		RuleName: "default",
		Action:   config.ActionBypass,
		NATIP:    m.defaultNATIP,
		Matched:  false,
	}
}

// ShouldNAT returns true if the destination should have NAT applied.
func (m *RuleMatcher) ShouldNAT(destIP net.IP) bool {
	result := m.Match(destIP)
	return result.Action == config.ActionNAT
}

// ShouldBypass returns true if the destination should bypass NAT.
func (m *RuleMatcher) ShouldBypass(destIP net.IP) bool {
	result := m.Match(destIP)
	return result.Action == config.ActionBypass
}
