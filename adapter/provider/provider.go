package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"

	"gopkg.in/yaml.v2"
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	*fetcher
	proxies     []C.Proxy
	healthCheck *HealthCheck
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        pp.Name(),
		"type":        pp.Type().String(),
		"vehicleType": pp.VehicleType().String(),
		"proxies":     pp.Proxies(),
		"updatedAt":   pp.updatedAt,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.name
}

func (pp *proxySetProvider) HealthCheck() {
	pp.healthCheck.check()
}

func (pp *proxySetProvider) Update() error {
	elm, same, err := pp.fetcher.Update()
	if err == nil && !same {
		pp.onUpdate(elm)
	}
	return err
}

func (pp *proxySetProvider) Initial() error {
	elm, err := pp.fetcher.Initial()
	if err != nil {
		return err
	}

	pp.onUpdate(elm)
	return nil
}

func (pp *proxySetProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pp *proxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *proxySetProvider) ProxiesWithTouch() []C.Proxy {
	pp.healthCheck.touch()
	return pp.Proxies()
}

func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)
	if pp.healthCheck.auto() {
		go pp.healthCheck.check()
	}
}

func stopProxyProvider(pd *ProxySetProvider) {
	pd.healthCheck.close()
	pd.fetcher.Destroy()
}

func NewProxySetProvider(name string, interval time.Duration, filter string, vehicle types.Vehicle, hc *HealthCheck) (*ProxySetProvider, error) {
	filterReg, err := regexp.Compile(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter regex: %w", err)
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &proxySetProvider{
		proxies:     []C.Proxy{},
		healthCheck: hc,
	}

	onUpdate := func(elm any) {
		ret := elm.([]C.Proxy)
		pd.setProxies(ret)
	}

	proxiesParseAndFilter := func(buf []byte) (any, error) {
		schema := &ProxySchema{}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			return nil, err
		}

		if schema.Proxies == nil {
			return nil, errors.New("file must have a `proxies` field")
		}

		proxies := []C.Proxy{}
		for idx, mapping := range schema.Proxies {
			if name, ok := mapping["name"]; ok && len(filter) > 0 && !filterReg.MatchString(name.(string)) {
				continue
			}
			proxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				return nil, fmt.Errorf("proxy %d error: %w", idx, err)
			}
			proxies = append(proxies, proxy)
		}

		if len(proxies) == 0 {
			if len(filter) > 0 {
				return nil, errors.New("doesn't match any proxy, please check your filter")
			}
			return nil, errors.New("file doesn't have any proxy")
		}

		return proxies, nil
	}

	fetcher := newFetcher(name, interval, vehicle, proxiesParseAndFilter, onUpdate)
	pd.fetcher = fetcher

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, stopProxyProvider)
	return wrapper, nil
}

// for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	name        string
	healthCheck *HealthCheck
	proxies     []C.Proxy
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        cp.Name(),
		"type":        cp.Type().String(),
		"vehicleType": cp.VehicleType().String(),
		"proxies":     cp.Proxies(),
	})
}

func (cp *compatibleProvider) Name() string {
	return cp.name
}

func (cp *compatibleProvider) HealthCheck() {
	cp.healthCheck.check()
}

func (cp *compatibleProvider) Update() error {
	return nil
}

func (cp *compatibleProvider) Initial() error {
	return nil
}

func (cp *compatibleProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (cp *compatibleProvider) Type() types.ProviderType {
	return types.Proxy
}

func (cp *compatibleProvider) Proxies() []C.Proxy {
	return cp.proxies
}

func (cp *compatibleProvider) ProxiesWithTouch() []C.Proxy {
	cp.healthCheck.touch()
	return cp.Proxies()
}

func stopCompatibleProvider(pd *CompatibleProvider) {
	pd.healthCheck.close()
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (*CompatibleProvider, error) {
	if len(proxies) == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &compatibleProvider{
		name:        name,
		proxies:     proxies,
		healthCheck: hc,
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, stopCompatibleProvider)
	return wrapper, nil
}

type RuleSetSchema struct {
	Payload []string `yaml:"payload"`
}

// for auto gc
type RuleSetProvider struct {
	*ruleSetProvider
}

type ruleSetProvider struct {
	*fetcher
	payload    []string
	ipcidrs    []*net.IPNet
	domainTrie *trie.DomainTrie
	adapter    string
	behavior   types.RuleType
}

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.fetcher.Initial()
	if err != nil {
		return err
	}

	rp.onUpdate(elm)
	return nil
}

func (rp *ruleSetProvider) Type() types.ProviderType {
	return types.Rule
}

func (rp *ruleSetProvider) RuleType() C.RuleType {
	return C.RuleSet
}

func (rp *ruleSetProvider) Update() error {
	elm, same, err := rp.fetcher.Update()
	if err == nil && !same {
		rp.onUpdate(elm)
	}
	return err
}

func (rp *ruleSetProvider) Behavior() types.RuleType {
	return rp.behavior
}

func (rp *ruleSetProvider) Match(metadata *C.Metadata) bool {
	if rp.behavior == types.IPCIDR {
		for _, ipcidr := range rp.ipcidrs {
			if ipcidr.Contains(metadata.DstIP) {
				return true
			}
		}
	} else if rp.behavior == types.Domain {
		if rp.domainTrie.Search(metadata.Host) != nil {
			return true
		}
	}
	return false
}

func (rp *ruleSetProvider) AsRule(adaptor string) C.Rule {
	rp.adapter = adaptor
	return rp
}

func (rp *ruleSetProvider) Adapter() string {
	return rp.adapter
}

func (rp *ruleSetProvider) Payload() string {
	return rp.payload[0]
}

func (rp *ruleSetProvider) ShouldResolveIP() bool {
	return false
}

func (rp *ruleSetProvider) ShouldFindProcess() bool {
	return false
}

func (rp *ruleSetProvider) setPayload(payload []string) {
	rp.payload = payload

	for _, payloadEntry := range payload {
		if rp.behavior == types.IPCIDR {
			_, ipnet, _ := net.ParseCIDR(payloadEntry)
			rp.ipcidrs = append(rp.ipcidrs, ipnet)
		} else if rp.behavior == types.Domain {
			rp.domainTrie.Insert(payloadEntry, true)
		}
	}
}

func stopRuleProvider(rp *RuleSetProvider) {
	rp.fetcher.Destroy()
}

func NewRuleSetProvider(name string, interval time.Duration, vehicle types.Vehicle, behavior types.RuleType) (*RuleSetProvider, error) {
	rp := &ruleSetProvider{
		payload:    []string{},
		ipcidrs:    []*net.IPNet{},
		domainTrie: trie.New(),
		behavior:   behavior,
	}

	onUpdate := func(elm any) {
		ret := elm.([]string)
		rp.setPayload(ret)
	}

	parsePayload := func(buf []byte) (any, error) {
		schema := &RuleSetSchema{}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			return nil, err
		}

		if schema.Payload == nil {
			return nil, errors.New("file must have a `payload` field")
		}

		if len(schema.Payload) == 0 {
			return nil, errors.New("payload is empty")
		}

		return schema.Payload, nil
	}

	fetcher := newFetcher(name, interval, vehicle, parsePayload, onUpdate)
	rp.fetcher = fetcher

	wrapper := &RuleSetProvider{rp}
	runtime.SetFinalizer(wrapper, stopRuleProvider)
	return wrapper, nil
}
