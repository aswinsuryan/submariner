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

package nftables

import (
	"context"
	goerrors "errors"

	"github.com/pkg/errors"
	"github.com/submariner-io/submariner/pkg/packetfilter"
	k8snet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

type namedSet struct {
	set      knftables.Set
	nftables knftables.Interface
}

func (p *packetFilter) NewNamedSet(set *packetfilter.SetInfo) packetfilter.NamedSet {
	setType := "ipv4_addr"
	if p.family == k8snet.IPv6 {
		setType = "ipv6_addr"
	}

	return &namedSet{
		set: knftables.Set{
			Name:  set.Name,
			Type:  setType,
			Flags: []knftables.SetFlag{knftables.IntervalFlag},
		},
		nftables: p.nftables,
	}
}

func (n *namedSet) Create(_ bool) error {
	tx := n.nftables.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: ptr.To("rules for submariner"),
	})

	tx.Add(&n.set)
	err := n.nftables.Run(context.TODO(), tx)

	return errors.Wrapf(err, "error creating set %q", n.Name())
}

func (n *namedSet) Name() string {
	return n.set.Name
}

func (n *namedSet) Flush() error {
	tx := n.nftables.NewTransaction()
	tx.Flush(&n.set)

	err := n.nftables.Run(context.TODO(), tx)
	if knftables.IsNotFound(err) {
		return nil
	}

	return errors.Wrapf(err, "error flushing set %q", n.Name())
}

func (n *namedSet) Destroy() error {
	return deleteSet(n.nftables, n.Name())
}

func (n *namedSet) AddEntry(entry string, _ bool) error {
	tx := n.nftables.NewTransaction()

	tx.Add(&knftables.Element{
		Set: n.Name(),
		Key: []string{entry},
	})

	err := n.nftables.Run(context.TODO(), tx)

	return errors.Wrapf(err, "error adding entry %q to set %q", entry, n.Name())
}

func (n *namedSet) DelEntry(entry string) error {
	tx := n.nftables.NewTransaction()

	tx.Delete(&knftables.Element{
		Set: n.Name(),
		Key: []string{entry},
	})

	err := n.nftables.Run(context.TODO(), tx)

	return errors.Wrapf(err, "error deleting entry %q from set %q", entry, n.Name())
}

func (n *namedSet) ListEntries() ([]string, error) {
	nftablesElems, err := n.nftables.ListElements(context.TODO(), "set", n.Name())
	if err != nil {
		return []string{}, errors.Wrapf(err, "error listing elements for set %q", n.Name())
	}

	strElems := []string{}

	for _, existingElem := range nftablesElems {
		strElems = append(strElems, existingElem.Key[0])
	}

	return strElems, nil
}

func (p *packetFilter) DestroySets(nameFilter func(string) bool) error {
	setsList, err := p.nftables.List(context.TODO(), "sets")
	if err != nil && !knftables.IsNotFound(err) {
		return errors.Wrap(err, "error listing sets")
	}

	var errs []error

	for _, set := range setsList {
		if nameFilter(set) {
			err = deleteSet(p.nftables, set)
			errs = append(errs, err)
		}
	}

	return goerrors.Join(errs...)
}

func deleteSet(nftables knftables.Interface, name string) error {
	tx := nftables.NewTransaction()
	tx.Delete(&knftables.Set{
		Name: name,
	})

	err := nftables.Run(context.TODO(), tx)
	if knftables.IsNotFound(err) {
		return nil
	}

	return errors.Wrapf(err, "error deleting set %q", name)
}
