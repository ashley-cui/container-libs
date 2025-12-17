package util

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"go.podman.io/common/libnetwork/types"
)

func CommonNetworkCreate(n NetUtil, newNetwork *types.Network) error {
	if newNetwork.Labels == nil {
		newNetwork.Labels = map[string]string{}
	}
	if newNetwork.Options == nil {
		newNetwork.Options = map[string]string{}
	}
	if newNetwork.IPAMOptions == nil {
		newNetwork.IPAMOptions = map[string]string{}
	}

	var name string
	var err error
	// validate the name when given
	if newNetwork.Name != "" {
		if !types.NameRegex.MatchString(newNetwork.Name) {
			return fmt.Errorf("network name %s invalid: %w", newNetwork.Name, types.ErrInvalidName)
		}
		if _, err := n.Network(newNetwork.Name); err == nil {
			return fmt.Errorf("network name %s already used: %w", newNetwork.Name, types.ErrNetworkExists)
		}
	} else {
		name, err = GetFreeDeviceName(n)
		if err != nil {
			return err
		}
		newNetwork.Name = name
		// also use the name as interface name when we create a bridge network
		if newNetwork.Driver == types.BridgeNetworkDriver && newNetwork.NetworkInterface == "" {
			newNetwork.NetworkInterface = name
		}
	}

	// Validate interface name if specified
	if newNetwork.NetworkInterface != "" {
		if err := ValidateInterfaceName(newNetwork.NetworkInterface); err != nil {
			return fmt.Errorf("network interface name %s invalid: %w", newNetwork.NetworkInterface, err)
		}
	}
	return nil
}

func IpamNoneDisableDNS(network *types.Network) {
	if network.IPAMOptions[types.Driver] == types.NoneIPAMDriver {
		logrus.Debugf("dns disabled for network %q because ipam driver is set to none", network.Name)
		network.DNSEnabled = false
	}
}
