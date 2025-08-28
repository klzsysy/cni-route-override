// Copyright 2019 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes route information given from
// previous cni plugins
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	log "github.com/k8snetworkplumbingwg/cni-log"
	"github.com/vishvananda/netlink"
)

func init() {
	log.SetLogFile("/var/log/cni-route-override.log")
}

const (
	ipv4DefaultRoute = "0.0.0.0/0"
	ipv6DefaultRoute = "::/0"
	defaultInf       = "eth0"
)

var extInf []string
var infNames []string

// Todo:
// + only checko route/dst
//go build ./cmd/route-override/

// RouteOverrideConfig represents the network route-override configuration
type RouteOverrideConfig struct {
	types.NetConf

	PrevResult        *current.Result `json:"-"`
	Debug             bool            `json:"debug,omitempty"`
	ExternalInterface []string        `json:"externalinterface,omitempty"`
	FlushRoutes       bool            `json:"flushroutes,omitempty"`
	FlushGateway      bool            `json:"flushgateway,omitempty"`
	DelRoutes         []*types.Route  `json:"delroutes"`
	AddRoutes         []*types.Route  `json:"addroutes"`
	SkipCheck         bool            `json:"skipcheck,omitempty"`

	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

// IPAMArgs represents CNI argument conventions for the plugin
type IPAMArgs struct {
	Debug        bool           `json:"debug,omitempty"`
	FlushRoutes  *bool          `json:"flushroutes,omitempty"`
	FlushGateway *bool          `json:"flushgateway,omitempty"`
	DelRoutes    []*types.Route `json:"delroutes,omitempty"`
	AddRoutes    []*types.Route `json:"addroutes,omitempty"`
	SkipCheck    *bool          `json:"skipcheck,omitempty"`
}

/*
	type RouteOverrideArgs struct {
		types.CommonArgs
	}
*/
func parseConf(data []byte, _ string) (*RouteOverrideConfig, error) {
	conf := RouteOverrideConfig{FlushRoutes: false}

	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v\n%s", err, string(data))
	}

	// override values by args
	if conf.Args != nil {
		log.Infof("Loading args: %v", conf.Args)
		if conf.Args.A.FlushRoutes != nil {
			conf.FlushRoutes = *conf.Args.A.FlushRoutes
		}

		if conf.Args.A.FlushGateway != nil {
			conf.FlushGateway = *conf.Args.A.FlushGateway
		}

		if conf.Args.A.DelRoutes != nil {
			conf.DelRoutes = conf.Args.A.DelRoutes
		}

		if conf.Args.A.AddRoutes != nil {
			conf.AddRoutes = conf.Args.A.AddRoutes
		}

		if conf.Args.A.SkipCheck != nil {
			conf.SkipCheck = *conf.Args.A.SkipCheck
		}
		if conf.Args.A.Debug {
			conf.Debug = true
		}
	}
	if conf.Debug {
		log.SetLogLevel(log.DebugLevel)
	}
	body, _ := json.Marshal(conf)
	log.Debugf("parsed configuration: %s", string(body))

	if conf.ExternalInterface != nil {
		log.Debugf("Extension processing interface: %s", conf.ExternalInterface)
		extInf = conf.ExternalInterface
	}

	// Parse previous result
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}

		res, err := version.NewResult(conf.CNIVersion, resultBytes)

		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}

		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	return &conf, nil
}

func deleteAllRoutes(res *current.Result) {
	log.Debugf("delete all routes")
	for _, netif := range ifNames(res) {
		link, err := netlink.LinkByName(netif)
		if err != nil {
			continue
		}
		routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			log.Warningf("failed to list routes %s: %v", netif, err)
			continue
		}
		for _, route := range routes {
			if route.Scope != netlink.SCOPE_LINK {
				if route.Dst != nil {
					if route.Dst.IP.IsLinkLocalUnicast() != true && route.Gw != nil {
						if err := netlink.RouteDel(&route); err != nil {
							log.Errorf("failed to delete route %s: %v", netif, route)
						} else {
							log.Infof("deleted route %s", route)
						}
					}
				} else {
					if err := netlink.RouteDel(&route); err != nil {
						log.Errorf("failed to delete route %s: %v", netif, err)
					} else {
						log.Infof("deleted default route %s", route)
					}
				}
			}
		}
	}
}

func deleteGWRoute(res *current.Result) {
	log.Infof("deleting default route")
	for _, netif := range ifNames(res) {
		link, err := netlink.LinkByName(netif)
		if err != nil {
			continue
		}
		routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			log.Errorf("failed to list routes %s: %v", netif, err)
			continue
		}
		for _, nlroute := range routes {
			// default route dst is nul.
			if nlroute.Dst == nil {
				if err := netlink.RouteDel(&nlroute); err != nil {
					log.Errorf("failed to delete route %s: %v", netif, err)
				} else {
					log.Debugf("deleted defaut route %s", nlroute)
				}
			}
		}
	}
}

func ifNames(res *current.Result) (infs []string) {
	if infNames != nil {
		return infNames
	}
	defer func() {
		infNames = infs
		log.Debugf("interface names: %s", infNames)
	}()
	if res.Interfaces != nil {
		for _, netif := range res.Interfaces {
			if netif.Sandbox != "" {
				infs = append(infs, netif.Name)
			}
		}
	}
	infs = append(infs, extInf...)
	if len(infs) == 0 {
		return []string{defaultInf}
	}
	if len(infs) == 1 {
		return infs
	}
	sort.SliceStable(infs, func(i, j int) bool { return infs[i] < infs[j] })
	slices.Compact(infs)
	return infs
}

func deleteRoute(route *types.Route, res *current.Result) error {
	var (
		err    error
		link   netlink.Link
		routes []netlink.Route
	)
	for _, inf := range ifNames(res) {
		log.Debugf("try deleting route %s by %s", route, inf)
		link, err = netlink.LinkByName(inf)
		if err != nil {
			log.Warningf("failed to link by name %s: %v", inf, err)
			continue
		}
		routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			log.Errorf("failed to list routes %s: %v", inf, err)
			continue
		}
		for _, nlroute := range routes {
			if (nlroute.Dst == nil && (route.Dst.String() == ipv4DefaultRoute || route.Dst.String() == ipv6DefaultRoute)) || nlroute.Dst.String() == route.Dst.String() {
				if route.GW != nil && !nlroute.Gw.Equal(route.GW) {
					log.Debugf("skip delete route, because the gateway does not match: %s", nlroute)
					continue
				}
				if err = netlink.RouteDel(&nlroute); err != nil {
					log.Errorf("failed to delete route %s: %v", inf, err)
				} else {
					log.Infof("deleted route %s %s", inf, nlroute)
					return nil
				}
			} else {
				log.Debugf("skip delete route %s by %s, except %s", nlroute.Dst.String(), inf, route.Dst.String())
			}
		}
	}
	return err
}

func addRoute(route *types.Route, result *current.Result) error {
	var (
		err   error
		netif netlink.Link
	)
	for _, inf := range ifNames(result) {
		netif, err = netlink.LinkByName(inf)
		if err != nil {
			log.Errorf("failed to link by name %s: %v", inf, err)
			continue
		}
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: netif.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &route.Dst,
			Gw:        route.GW,
			Priority:  route.Priority,
		})
		if err == nil {
			log.Infof("added route %v by %s", route, inf)
			return nil
		}
	}
	return err
}

func processRoutes(netnsname string, conf *RouteOverrideConfig) (*current.Result, error) {
	netns, err := ns.GetNS(netnsname)
	if err != nil {
		return nil, fmt.Errorf("failed to get netns %s: %v", netnsname, err)
	}
	defer netns.Close()

	res, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	if conf.FlushGateway {
		// add "0.0.0.0/0" into delRoute to remove it from routing table/result
		_, gwRoute, _ := net.ParseCIDR(ipv4DefaultRoute)
		conf.DelRoutes = append(conf.DelRoutes, &types.Route{Dst: *gwRoute})
		_, gwRoute, _ = net.ParseCIDR(ipv6DefaultRoute)
		conf.DelRoutes = append(conf.DelRoutes, &types.Route{Dst: *gwRoute})

		// delete given gateway address
		for _, ips := range res.IPs {
			if ips.Address.IP.To4() == nil {
				ips.Gateway = net.IPv6zero
			} else {
				ips.Gateway = net.IPv4zero
			}
		}
	}

	newRoutes := map[string]*types.Route{}
	if err = netns.Do(func(_ ns.NetNS) error {
		// Flush route if required
		if !conf.FlushRoutes {
			for _, delroute := range conf.DelRoutes {
				if err = deleteRoute(delroute, res); err != nil {
					return err
				}
				for _, route := range res.Routes {
					if route.Dst.IP.Equal(delroute.Dst.IP) &&
						bytes.Equal(route.Dst.Mask, delroute.Dst.Mask) {
						continue
					}
					newRoutes[route.String()] = route
				}
			}
		} else {
			deleteAllRoutes(res)
		}

		if conf.FlushGateway && !conf.FlushRoutes {
			deleteGWRoute(res)
		}
		// Add route
		for _, route := range conf.AddRoutes {
			if err = addRoute(route, res); err != nil {
				return log.Errorf("failed to add route %+v: %v", route, err)
			}
			newRoutes[route.String()] = route
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var r []*types.Route
	for _, route := range newRoutes {
		r = append(r, route)
	}
	res.Routes = r
	return res, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Infof("ADD: [args:%s],[netns:%s],[ifName:%s],[containerID:%s]", args.Args, args.Netns, args.IfName, args.ContainerID)
	overrideConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	newResult, err := processRoutes(args.Netns, overrideConf)
	if err != nil {
		return fmt.Errorf("failed to override routes: %v", err)
	}

	return types.PrintResult(newResult, overrideConf.CNIVersion)
}

func cmdDel(_ *skel.CmdArgs) error {
	// TODO: the settings are not reverted to the previous values. Reverting the
	// settings is not useful when the whole container goes away but it could be
	// useful in scenarios where plugins are added and removed at runtime.
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	log.Infof("CHECK: [args:%s],[netns:%s],[ifName:%s],[containerID:%s]", args.Args, args.Netns, args.IfName, args.ContainerID)
	// Parse previous result
	overrideConf, err := parseConf(args.StdinData, args.Args)

	if err != nil {
		return err
	}

	// if skipcheck is true, skip it
	if overrideConf.SkipCheck == true {
		return nil
	}

	if overrideConf.PrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&overrideConf.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(overrideConf.PrevResult)
	if err != nil {
		return err
	}

	gateways := []net.IP{}
	for _, i := range result.IPs {
		gateways = append(gateways, i.Gateway)
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		for _, cniRoute := range overrideConf.DelRoutes {
			_, err := netlink.RouteGet(cniRoute.Dst.IP)
			if err == nil {
				return fmt.Errorf("route-override: route is not removed: %v", cniRoute)
			}
		}

		for _, cniRoute := range result.Routes {
			var routes []netlink.Route
			if cniRoute.Dst.IP.Equal(net.ParseIP("0.0.0.0")) == true || cniRoute.Dst.IP.Equal(net.ParseIP("::")) {
				family := netlink.FAMILY_ALL
				if cniRoute.Dst.IP.To4() == nil {
					family = netlink.FAMILY_V6
				} else {
					family = netlink.FAMILY_V4
				}
				filter := &netlink.Route{
					Dst: nil,
				}
				routes, err = netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST)
				if err != nil {
					return err
				}
			} else {
				routes, err = netlink.RouteGet(cniRoute.Dst.IP)
				if err != nil {
					return err
				}
			}

			if len(routes) != 1 {
				return fmt.Errorf("route-override: got multiple routes: %v", routes)
			}

			// if gateway in cni result is nil, then lookup gateways in interface of cni result
			if cniRoute.GW == nil {
				found := false
				for _, gw := range gateways {
					if gw.Equal(routes[0].Gw) {
						found = true
					}
				}
				if found != true {
					return fmt.Errorf("route-override: cannot find gateway %v in result: %v", cniRoute.GW, routes[0].Gw)
				}
			} else {
				if routes[0].Gw.Equal(cniRoute.GW) != true {
					return fmt.Errorf("route-override: failed to match route: %v %v", cniRoute, routes[0].Gw)
				}
			}
		}
		return nil
	})

	return err
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{Add: cmdAdd, Check: cmdCheck, Del: cmdDel}, version.All, "route-override v0.1.0-dev")
}
