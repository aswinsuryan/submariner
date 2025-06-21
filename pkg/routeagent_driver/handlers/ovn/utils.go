/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ovn

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/pkg/errors"
	subMNetLink "github.com/submariner-io/submariner/pkg/netlink"
	k8snet "k8s.io/utils/net"
)

func getNextHopOnK8sMgmtIntf(family k8snet.IPFamily) (string, error) {
	netLink := subMNetLink.New()

	link, err := netLink.LinkByName(OVNK8sMgmntIntfName)
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve link by name %q", OVNK8sMgmntIntfName)
	}

	addrs, err := netLink.AddrList(link, family)
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve %v addresses for link %q", family, OVNK8sMgmntIntfName)
	}

	for _, addr := range addrs {
		if addr.IPNet != nil {
			return addr.IPNet.IP.String(), nil
		}
	}

	return "", errors.Errorf("no %v address found on interface %q", family, OVNK8sMgmntIntfName)
}

func jsonToIP(jsonData string, family k8snet.IPFamily) (string, error) {
	var data map[string]string

	err := json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return "", errors.Wrapf(err, "error unmarshalling the JSON IP")
	}

	ipStr := data["ipv"+string(family)]
	if ipStr == "" {
		return "", errors.Errorf("JSON data does not contain 'ipv%s' field", family)
	}

	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		return "", fmt.Errorf("invalid IP CIDR address: %s", ipStr)
	}

	return ip.String(), nil
}

// familySuffix "-v6" for CR name uniqueness.
func familySuffix(f k8snet.IPFamily) string {
	if f == k8snet.IPv6 {
		return "-v6"
	}

	return ""
}
