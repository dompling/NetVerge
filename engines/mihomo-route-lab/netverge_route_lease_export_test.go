// Copied into the pinned upstream tunnel package only for go test.
// Expose the actual unexported resolver to the external test package without
// importing adapter/outbound (which imports dns, which imports tunnel).
package tunnel

import C "github.com/metacubex/mihomo/constant"

func NetVergeLabResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveMetadata(metadata)
}

// This laboratory is serial and owns the test process's global state.
func NetVergeLabRestoreState() func() {
	oldRules, oldSubRules, oldRuleProviders := rules, subRules, ruleProviders
	oldProxies, oldProviders := proxies, providers
	oldMode, oldFindProcess := Mode(), FindProcessMode()
	return func() {
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		UpdateProxies(oldProxies, oldProviders)
		SetMode(oldMode)
		SetFindProcessMode(oldFindProcess)
	}
}
