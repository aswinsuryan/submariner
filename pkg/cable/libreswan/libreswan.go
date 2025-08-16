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

// Package libreswan provides an IPSec cable driver implementation using Libreswan.
//
// Authentication Modes:
//   - PSK Mode (default): Set CE_IPSEC_AUTHMODE=psk or leave unset
//   - Certificate Mode: Set CE_IPSEC_AUTHMODE=cert
//
// If CE_IPSEC_AUTHMODE is not set or empty, PSK mode is used by default.
// PSK Mode uses pre-shared keys for authentication (traditional method).
// Certificate Mode uses automatically managed X.509 certificates for mutual authentication.
package libreswan

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/submariner-io/admiral/pkg/syncer/broker"
	"k8s.io/client-go/dynamic"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/command"
	"github.com/submariner-io/admiral/pkg/log"
	subv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	submendpoint "github.com/submariner-io/submariner/pkg/endpoint"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	k8snet "k8s.io/utils/net"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	cableDriverName  = "libreswan"
	whackTimeout     = 5 * time.Second
	dpdDelay         = 30 // seconds
	encryptArg       = "--encrypt"
	forceencapsArg   = "--forceencaps"
	nameArg          = "--name"
	hostArg          = "--host"
	clientArg        = "--client"
	ikeportArg       = "--ikeport"
	dpdactionHoldArg = "--dpdaction=hold"
	dpddelayArg      = "--dpddelay"
	// Certificate authentication arguments
	certArg = "--cert"
	caArg   = "--ca"
)

// AuthMode defines the authentication mode for libreswan
type AuthMode string

const (
	// AuthModePSK uses Pre-Shared Key authentication
	AuthModePSK AuthMode = "psk"
	// AuthModeCert uses certificate-based authentication
	AuthModeCert AuthMode = "cert"
)

var (
	logger       = log.Logger{Logger: logf.Log.WithName("libreswan")}
	ipFamilyArgs = map[k8snet.IPFamily]string{
		k8snet.IPv4: "--ipv4",
		k8snet.IPv6: "--ipv6",
	}

	PlutoCtlSocketTimeout = time.Minute
	RootDir               = ""
	FatalError            = func(err error, msg string) {
		logger.FatalOnError(err, msg)
	}
)

func init() {
	cable.AddDriver(cableDriverName, NewLibreswan)
	cable.SetDefaultCableDriver(cableDriverName)
}

type libreswan struct {
	syncerConfig broker.SyncerConfig
	brokerClient dynamic.Interface

	localEndpoint subv1.EndpointSpec
	// This tracks the requested connections
	connections []subv1.Connection

	secretKey string
	logFile   string

	ipSecNATTPort   string
	defaultNATTPort int32

	debug                 bool
	forceUDPEncapsulation bool
	plutoStarted          bool
	authMode              AuthMode

	stopCh                chan struct{}
	certificateController *CertificateController
}

type specification struct {
	Debug       bool
	ForceEncaps bool
	PSK         string
	PSKSecret   string
	LogFile     string
	NATTPort    string `default:"4500"`
	AuthMode    string `default:"psk"` // Authentication mode: "psk" or "cert"
}

// NewLibreswan starts an IKE daemon using Libreswan and configures it to manage Submariner's endpoints.
func NewLibreswan(syncerConfig broker.SyncerConfig, brokerClient dynamic.Interface, localEndpoint *submendpoint.Local, _ *types.SubmarinerCluster) (cable.Driver, error) {
	// We'll panic if localEndpoint is nil, this is intentional
	ipSecSpec := specification{}

	err := envconfig.Process(cable.IPSecEnvPrefix, &ipSecSpec)
	if err != nil {
		return nil, errors.Wrapf(err, "error processing environment config for %s", cable.IPSecEnvPrefix)
	}

	// Parse and validate authentication mode with fallback to PSK
	//authModeStr := strings.ToLower(strings.TrimSpace(ipSecSpec.AuthMode))
	authModeStr := "cert"
	if authModeStr == "" {
		// Fallback to default PSK mode if not set
		authModeStr = "cert"
		logger.Info("CE_IPSEC_AUTHMODE not set, defaulting to certificate authentication")
	}

	authMode := AuthMode(authModeStr)
	if authMode != AuthModePSK && authMode != AuthModeCert {
		return nil, fmt.Errorf("invalid authentication mode %q, must be 'psk' or 'cert'", authModeStr)
	}

	port, err := strconv.ParseUint(ipSecSpec.NATTPort, 10, 16)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing CE_IPSEC_NATTPORT environment variable")
	}

	defaultNATTPort := int32(port)

	nattPort, err := localEndpoint.Spec().GetBackendPort(subv1.UDPPortConfig, defaultNATTPort)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %q from local endpoint", subv1.UDPPortConfig)
	}

	err = processPreferredServerConfig(localEndpoint)
	if err != nil {
		return nil, err
	}

	var encodedPsk string

	// Only process PSK if using PSK authentication mode
	if authMode == AuthModePSK {
		encodedPsk = ipSecSpec.PSK

		if ipSecSpec.PSKSecret != "" {
			pskBytes, err := os.ReadFile(RootDir + fmt.Sprintf("/var/run/secrets/submariner.io/%s/psk", ipSecSpec.PSKSecret))
			if err != nil {
				return nil, errors.Wrapf(err, "error reading secret %s", ipSecSpec.PSKSecret)
			}
			var psk strings.Builder
			encoder := base64.NewEncoder(base64.StdEncoding, &psk)

			if _, err := encoder.Write(pskBytes); err != nil {
				return nil, errors.Wrap(err, "error encoding secret")
			}

			encoder.Close()

			encodedPsk = psk.String()
		}
	}

	logger.Infof("Using NATT UDP port %d with authentication mode: %s", nattPort, authMode)

	return &libreswan{
		secretKey:             encodedPsk,
		debug:                 ipSecSpec.Debug,
		logFile:               ipSecSpec.LogFile,
		ipSecNATTPort:         strconv.Itoa(int(nattPort)),
		defaultNATTPort:       defaultNATTPort,
		localEndpoint:         *localEndpoint.Spec(),
		connections:           []subv1.Connection{},
		forceUDPEncapsulation: ipSecSpec.ForceEncaps,
		syncerConfig:          syncerConfig,
		plutoStarted:          false,
		brokerClient:          brokerClient,
		authMode:              authMode,
	}, nil
}

// GetName returns driver's name.
func (i *libreswan) GetName() string {
	return cableDriverName
}

// buildAuthArgs returns the appropriate authentication arguments based on the auth mode
func (i *libreswan) buildAuthArgs() []string {
	var authArgs []string

	switch i.authMode {
	case AuthModePSK:
		// PSK authentication using pre-shared key
		authArgs = append(authArgs, "--psk", encryptArg)

	case AuthModeCert:
		// Certificate authentication using NSS database certificates
		certName := fmt.Sprintf("submariner-client-%s", i.localEndpoint.ClusterID)
		caName := "submariner-ca"

		authArgs = append(authArgs,
			certArg, certName, // Client certificate name in NSS
			caArg, caName, // CA certificate name in NSS
			encryptArg) // Enable encryption

	default:
		// Fallback to PSK (should not happen due to validation in NewLibreswan)
		logger.Warningf("Unknown authentication mode %s, falling back to PSK", i.authMode)
		authArgs = append(authArgs, "--psk", encryptArg)
	}

	return authArgs
}

// Init initializes the driver with any state it needs.
func (i *libreswan) Init() error {
	logger.Infof("Initializing libreswan driver with authentication mode: %s", i.authMode)

	if i.authMode == AuthModePSK {
		// PSK Authentication Mode
		logger.Info("Setting up PSK authentication")

		// Write the secrets file: %any %any : PSK "secret"
		file, err := os.Create(RootDir + "/etc/ipsec.d/submariner.secrets")
		if err != nil {
			return errors.Wrap(err, "error creating the secrets file")
		}
		defer file.Close()

		fmt.Fprintf(file, "%%any %%any : PSK \"%s\"\n", i.secretKey)
		logger.Info("PSK secrets file created successfully")

	} else if i.authMode == AuthModeCert {
		// Certificate Authentication Mode
		logger.Info("Setting up certificate authentication")

		logger.Infof("Starting certificate creation Private IPs %s Public IPs %s", i.localEndpoint.PrivateIPs, i.localEndpoint.PublicIPs)
		sanIPs := append(i.localEndpoint.PrivateIPs, i.localEndpoint.PublicIPs...)
		err := i.EnsureCertificateSecret(i.localEndpoint.ClusterID, sanIPs)
		if err != nil {
			logger.Warningf("Unable to ensure certificate: %v", err)
		}

		csrSyncer, err := SetupCertificateSecretSyncer(i.syncerConfig)
		if err != nil {
			return fmt.Errorf("failed to setup CSR syncer: %w", err)
		}

		// Store stopCh in struct so you can close it on cleanup
		i.stopCh = make(chan struct{})

		go func() {
			if err := csrSyncer.Start(i.stopCh); err != nil {
				logger.Error(err, "CSR syncer failed")
			}
		}()

		// Start certificate controller to watch and load certificates into NSS database
		certController := NewCertificateController(i.syncerConfig.LocalClient, i.localEndpoint.ClusterID)
		if err := certController.Start(); err != nil {
			logger.Error(err, "Failed to start certificate controller")
			return errors.Wrap(err, "error starting certificate controller")
		}

		// Store controller for cleanup
		i.certificateController = certController

		logger.Info("Started certificate syncers and controller")
	} else {
		return fmt.Errorf("unsupported authentication mode: %s", i.authMode)
	}

	return nil
}

// Line format:
// 006 #3: "submariner-cable-cluster3-172-17-0-8-v4-0-0", type=ESP, add_time=1590508783, inBytes=0, outBytes=0, id='172.17.0.8'
// or:
// 006 #2: "submariner-cable-cluster3-172-17-0-8-v4-0-0"[1] 3.139.75.179, type=ESP, add_time=1617195756, inBytes=0, outBytes=0, \
// id='@10.0.63.203-0-0'"
// .
var TrafficStatusRE = regexp.MustCompile(`.* "([^"]+-v[46]-[0-1]-[0-1])"[^,]*, .*inBytes=(\d+), outBytes=(\d+).*`)

func retrieveActiveConnectionStats() (map[string]int, map[string]int, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), whackTimeout)
	defer cancel()

	// Retrieve active tunnels from the daemon
	cmd := command.New(exec.CommandContext(ctx, "/usr/sbin/ipsec", "whack", "--trafficstatus"))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "error retrieving whack's stdout")
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, errors.WithMessage(err, "error starting whack")
	}

	scanner := bufio.NewScanner(stdout)
	activeConnectionsRx := make(map[string]int)
	activeConnectionsTx := make(map[string]int)

	for scanner.Scan() {
		line := scanner.Text()

		matches := TrafficStatusRE.FindStringSubmatch(line)
		if matches != nil {
			_, ok := activeConnectionsRx[matches[1]]
			if !ok {
				activeConnectionsRx[matches[1]] = 0
			}

			_, ok = activeConnectionsTx[matches[1]]
			if !ok {
				activeConnectionsTx[matches[1]] = 0
			}

			inBytes, err := strconv.Atoi(matches[2])
			if err != nil {
				logger.Warningf("Invalid inBytes in whack output line: %q", line)
			} else {
				activeConnectionsRx[matches[1]] += inBytes
			}

			outBytes, err := strconv.Atoi(matches[3])
			if err != nil {
				logger.Warningf("Invalid outBytes in whack output line: %q", line)
			} else {
				activeConnectionsTx[matches[1]] += outBytes
			}
		} else {
			logger.V(log.DEBUG).Infof("Ignoring whack output line: %q", line)
		}
	}

	return activeConnectionsRx, activeConnectionsTx, errors.Wrap(cmd.Wait(), "error waiting for whack to complete")
}

func toConnectionName(cableName string, family k8snet.IPFamily, lsi, rsi int) string {
	return fmt.Sprintf("%s-v%s-%d-%d", cableName, family, lsi, rsi)
}

func (i *libreswan) refreshConnectionStatus() error {
	activeConnectionsRx, activeConnectionsTx, err := retrieveActiveConnectionStats()
	if err != nil {
		return err
	}

	localSubnetsByFamily := make(map[k8snet.IPFamily][]string)

	localSubnetsByFamily[k8snet.IPv4] = i.localEndpoint.ExtractSubnetsExcludingIP(i.localEndpoint.GetPrivateIP(k8snet.IPv4))
	localSubnetsByFamily[k8snet.IPv6] = i.localEndpoint.ExtractSubnetsExcludingIP(i.localEndpoint.GetPrivateIP(k8snet.IPv6))

	for j := range i.connections {
		isConnected := false

		connectionFamily := i.connections[j].GetFamily()
		remoteSubnets := i.connections[j].Endpoint.ExtractSubnetsExcludingIP(i.connections[j].Endpoint.GetPrivateIP(connectionFamily))

		rx, tx := 0, 0

		for lsi := range localSubnetsByFamily[connectionFamily] {
			for rsi := range remoteSubnets {
				connectionName := toConnectionName(i.connections[j].Endpoint.CableName, connectionFamily, lsi, rsi)
				subRx, okRx := activeConnectionsRx[connectionName]
				subTx, okTx := activeConnectionsTx[connectionName]

				if okRx || okTx {
					i.connections[j].Status = subv1.Connected
					isConnected = true
					rx += subRx
					tx += subTx
				} else {
					logger.V(log.DEBUG).Infof("Connection %q not found in active connections obtained from whack: %v, %v",
						connectionName, activeConnectionsRx, activeConnectionsTx)
				}
			}
		}

		cable.RecordConnection(cableDriverName, &i.localEndpoint, &i.connections[j].Endpoint, string(i.connections[j].Status), false,
			connectionFamily)
		cable.RecordRxBytes(cableDriverName, &i.localEndpoint, &i.connections[j].Endpoint, rx, connectionFamily)
		cable.RecordTxBytes(cableDriverName, &i.localEndpoint, &i.connections[j].Endpoint, tx, connectionFamily)

		if !isConnected {
			// Pluto should be connecting for us
			i.connections[j].Status = subv1.Connecting
			cable.RecordConnection(cableDriverName, &i.localEndpoint, &i.connections[j].Endpoint, string(i.connections[j].Status), false,
				connectionFamily)
			logger.V(log.DEBUG).Infof("Connection %q not found in active connections obtained from whack: %v, %v",
				i.connections[j].Endpoint.CableName, activeConnectionsRx, activeConnectionsTx)
		}
	}

	return nil
}

// GetActiveConnections returns an array of all the active connections.
func (i *libreswan) GetActiveConnections() ([]subv1.Connection, error) {
	return i.connections, nil
}

// GetConnections() returns an array of the existing connections, including status and endpoint info.
func (i *libreswan) GetConnections() ([]subv1.Connection, error) {
	if !i.plutoStarted {
		return []subv1.Connection{}, nil
	}

	if err := i.refreshConnectionStatus(); err != nil {
		return []subv1.Connection{}, err
	}

	return i.connections, nil
}

func whack(args ...string) error {
	var err error

	for range 3 {
		err = func() error {
			ctx, cancel := context.WithTimeout(context.TODO(), whackTimeout)
			defer cancel()

			fullArgs := append([]string{"whack"}, args...)
			cmd := exec.CommandContext(ctx, "/usr/sbin/ipsec", fullArgs...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			logger.V(log.TRACE).Infof("Whacking with %v", args)

			return command.New(cmd).Run()
		}()

		if err == nil {
			break
		}

		logger.Warningf("error %v whacking with args: %v", err, args)
		time.Sleep(1 * time.Second)
	}

	return errors.Wrapf(err, "error whacking with args %v", args)
}

// ConnectToEndpoint establishes a connection to the given endpoint and returns a string
// representation of the IP address of the target endpoint.
func (i *libreswan) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	if i.authMode == AuthModeCert {
		return i.connectToEndpointCertMode(endpointInfo)
	}
	return i.connectToEndpointPSKMode(endpointInfo)
}

// connectToEndpointCertMode handles connection setup in certificate mode
func (i *libreswan) connectToEndpointCertMode(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	logger.Info("Certificate mode: skipping pluto start and whack; assuming pluto is managed externally and config/NSS DB are updated.")

	// Write submariner.conf
	confPath := "/etc/ipsec.d/submariner.conf"
	endpoint := &endpointInfo.Endpoint
	leftID := fmt.Sprintf("submariner-client-%s", i.localEndpoint.ClusterID)
	//rightID := fmt.Sprintf("submariner-client-%s", endpoint.Spec.ClusterID)
	connName := endpoint.Spec.CableName
	left := i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily)
	right := endpointInfo.UseIP
	leftSubnets := i.localEndpoint.Subnets
	rightSubnets := endpoint.Spec.Subnets

	/*leftNATTPort, err := i.localEndpoint.GetBackendPort(subv1.UDPPortConfig, i.defaultNATTPort)
	if err != nil {
		return "", errors.Wrapf(err, "error parsing %q from local endpoint", subv1.UDPPortConfig)
	}
	rightNATTPort, err := endpoint.Spec.GetBackendPort(subv1.UDPPortConfig, i.defaultNATTPort)
	if err != nil {
		return "", errors.Wrapf(err, "error parsing %q from local endpoint", subv1.UDPPortConfig)
	}*/

	conf := fmt.Sprintf(`conn %s
    left=%s
    leftid=%%fromcert
    leftcert=%s
    leftrsasigkey=%%cert
    leftsubnet=%s
    leftmodecfgclient=false
    right=%s
    rightid=%%fromcert
    rightsubnet=%s
    auto=add
    ikev2=insist
    authby=rsasig
    type=tunnel
`,
		connName,
		left,
		leftID,
		joinSubnets(leftSubnets),
		right,
		joinSubnets(rightSubnets),
	)

	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		logger.Errorf(err, "Failed to write %s", confPath)
		return "", err
	}
	logger.Infof("Wrote Libreswan connection config to %s", confPath)
	return "", nil
}

// connectToEndpointPSKMode handles connection setup in PSK mode
func (i *libreswan) connectToEndpointPSKMode(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	if !i.plutoStarted {
		// Ensure Pluto is started
		if err := i.runPluto(); err != nil {
			FatalError(err, "Error running Pluto")
		}
		i.plutoStarted = true
	}

	// We'll panic if endpointInfo is nil, this is intentional
	endpoint := &endpointInfo.Endpoint

	rightNATTPort, err := endpoint.Spec.GetBackendPort(subv1.UDPPortConfig, i.defaultNATTPort)
	if err != nil {
		logger.Warningf("Error parsing %q from remote endpoint %q - using port %d instead: %v", subv1.UDPPortConfig,
			endpoint.Spec.CableName, i.defaultNATTPort, err)
	}

	leftSubnets := i.localEndpoint.ExtractSubnetsExcludingIP(endpointInfo.UseIP)
	rightSubnets := endpoint.Spec.ExtractSubnetsExcludingIP(endpointInfo.UseIP)

	// Ensure we’re listening
	if err := whack("--listen"); err != nil {
		return "", errors.Wrap(err, "error listening")
	}

	connectionMode := i.calculateOperationMode(&endpoint.Spec)

	logger.Infof("Creating IPv%v connection(s) for %v in %s mode with %s authentication",
		endpointInfo.UseFamily, endpoint, connectionMode, i.authMode)

	if len(leftSubnets) > 0 && len(rightSubnets) > 0 {
		for lsi, leftSubnet := range leftSubnets {
			for rsi, rightSubnet := range rightSubnets {
				connectionName := toConnectionName(endpoint.Spec.CableName, endpointInfo.UseFamily, lsi, rsi)

				switch connectionMode {
				case operationModeBidirectional:
					err = i.bidirectionalConnectToEndpoint(connectionName, endpointInfo, leftSubnet, rightSubnet, rightNATTPort)
				case operationModeServer:
					err = i.serverConnectToEndpoint(connectionName, endpointInfo, leftSubnet, rightSubnet, lsi, rsi)
				case operationModeClient:
					err = i.clientConnectToEndpoint(connectionName, endpointInfo, leftSubnet, rightSubnet, rightNATTPort, lsi, rsi)
				}

				if err != nil {
					return "", err
				}
			}
		}
	}

	i.connections = append(i.connections,
		subv1.Connection{Endpoint: endpoint.Spec, Status: subv1.Connected, UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT})
	cable.RecordConnection(cableDriverName, &i.localEndpoint, &endpoint.Spec, string(subv1.Connected), true, endpointInfo.UseFamily)

	return endpointInfo.UseIP, nil
}

func (i *libreswan) bidirectionalConnectToEndpoint(connectionName string, endpointInfo *natdiscovery.NATEndpointInfo,
	leftSubnet, rightSubnet string, rightNATTPort int32,
) error {
	// Identifiers are used for authentication, they’re always the private IPs
	localEndpointIdentifier := i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily)
	remoteEndpointIdentifier := endpointInfo.Endpoint.Spec.GetPrivateIP(endpointInfo.UseFamily)

	args := []string{}

	// Add authentication arguments based on auth mode (PSK or certificate)
	args = append(args, i.buildAuthArgs()...)
	if endpointInfo.UseNAT || i.forceUDPEncapsulation {
		args = append(args, forceencapsArg)
	}

	args = append(args, nameArg, connectionName, ipFamilyArgs[endpointInfo.UseFamily],

		// Left-hand side
		"--id", localEndpointIdentifier,
		hostArg, i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily),
		clientArg, leftSubnet,

		ikeportArg, i.ipSecNATTPort,

		"--to",

		// Right-hand side
		"--id", remoteEndpointIdentifier,
		hostArg, endpointInfo.UseIP,
		clientArg, rightSubnet,

		ikeportArg, strconv.Itoa(int(rightNATTPort)),
		dpdactionHoldArg,
		dpddelayArg, strconv.Itoa(dpdDelay))

	logger.Infof("bidirectionalConnectToEndpoint: executing whack with args: %v", args)

	if err := whack(args...); err != nil {
		return err
	}

	if err := whack("--route", nameArg, connectionName); err != nil {
		return err
	}

	return whack("--initiate", "--asynchronous", nameArg, connectionName)
}

func toEndpointIdentifier(ip string, lsi, rsi int) string {
	return fmt.Sprintf("@%s-%d-%d", ip, lsi, rsi)
}

func (i *libreswan) serverConnectToEndpoint(connectionName string, endpointInfo *natdiscovery.NATEndpointInfo,
	leftSubnet, rightSubnet string, lsi, rsi int,
) error {
	localEndpointIdentifier := toEndpointIdentifier(i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily), lsi, rsi)
	remoteEndpointIdentifier := toEndpointIdentifier(endpointInfo.Endpoint.Spec.GetPrivateIP(endpointInfo.UseFamily), rsi, lsi)

	args := []string{}

	// Add authentication arguments based on auth mode (PSK or certificate)
	args = append(args, i.buildAuthArgs()...)
	if endpointInfo.UseNAT || i.forceUDPEncapsulation {
		args = append(args, forceencapsArg)
	}

	args = append(args, nameArg, connectionName, ipFamilyArgs[endpointInfo.UseFamily],

		// Left-hand side.
		"--id", localEndpointIdentifier,
		hostArg, i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily),
		clientArg, leftSubnet,

		ikeportArg, i.ipSecNATTPort,

		"--to",

		// Right-hand side.
		"--id", remoteEndpointIdentifier,
		hostArg, "%any",
		clientArg, rightSubnet,
		dpdactionHoldArg,
		dpddelayArg, strconv.Itoa(dpdDelay))

	logger.Infof("serverConnectToEndpoint: executing whack with args: %v", args)

	if err := whack(args...); err != nil {
		return err
	}

	// NOTE: in this case we don't route or initiate connection, we simply wait for the client
	// to connect from %any IP, using the right PSK & ID.
	return nil
}

func (i *libreswan) clientConnectToEndpoint(connectionName string, endpointInfo *natdiscovery.NATEndpointInfo,
	leftSubnet, rightSubnet string, rightNATTPort int32, lsi, rsi int,
) error {
	// Identifiers are used for authentication, they’re always the private IPs.
	localEndpointIdentifier := toEndpointIdentifier(i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily), lsi, rsi)
	remoteEndpointIdentifier := toEndpointIdentifier(endpointInfo.Endpoint.Spec.GetPrivateIP(endpointInfo.UseFamily), rsi, lsi)

	args := []string{}

	// Add authentication arguments based on auth mode (PSK or certificate)
	args = append(args, i.buildAuthArgs()...)
	if endpointInfo.UseNAT || i.forceUDPEncapsulation {
		args = append(args, forceencapsArg)
	}

	args = append(args, nameArg, connectionName, ipFamilyArgs[endpointInfo.UseFamily],

		// Left-hand side
		"--id", localEndpointIdentifier,
		hostArg, i.localEndpoint.GetPrivateIP(endpointInfo.UseFamily),
		clientArg, leftSubnet,

		"--to",

		// Right-hand side
		"--id", remoteEndpointIdentifier,
		hostArg, endpointInfo.UseIP,
		clientArg, rightSubnet,

		ikeportArg, strconv.Itoa(int(rightNATTPort)),
		dpdactionHoldArg,
		dpddelayArg, strconv.Itoa(dpdDelay))

	logger.Infof("clientConnectToEndpoint: executing whack with args: %v", args)

	if err := whack(args...); err != nil {
		return err
	}

	if err := whack("--route", nameArg, connectionName); err != nil {
		return err
	}

	return whack("--initiate", "--asynchronous", nameArg, connectionName)
}

// DisconnectFromEndpoint disconnects from the connection to the given endpoint.
func (i *libreswan) DisconnectFromEndpoint(endpoint *types.SubmarinerEndpoint, family k8snet.IPFamily) error {
	// We'll panic if endpoint is nil, this is intentional
	leftSubnets := i.localEndpoint.ExtractSubnetsExcludingIP(i.localEndpoint.GetPrivateIP(family))
	rightSubnets := endpoint.Spec.ExtractSubnetsExcludingIP(endpoint.Spec.GetPrivateIP(family))

	logger.Infof("Deleting IPv%v connection to %v", family, endpoint)

	if len(leftSubnets) > 0 && len(rightSubnets) > 0 {
		for lsi := range leftSubnets {
			for rsi := range rightSubnets {
				connectionName := toConnectionName(endpoint.Spec.CableName, family, lsi, rsi)
				args := []string{"--delete", nameArg, connectionName}

				if err := whack(args...); err != nil {
					var exitError *exec.ExitError
					if errors.As(err, &exitError) {
						logger.Errorf(err, "Error deleting a connection with args %v; got exit code %d", args, exitError.ExitCode())
					} else {
						return errors.Wrapf(err, "error deleting a connection with args %v", args)
					}
				}
			}
		}
	}

	i.connections = removeConnectionForEndpoint(i.connections, endpoint, family)
	cable.RecordDisconnected(cableDriverName, &i.localEndpoint, &endpoint.Spec, family)

	return nil
}

func removeConnectionForEndpoint(
	connections []subv1.Connection,
	endpoint *types.SubmarinerEndpoint,
	family k8snet.IPFamily,
) []subv1.Connection {
	for j := range connections {
		if connections[j].Endpoint.CableName == endpoint.Spec.CableName && connections[j].GetFamily() == family {
			copy(connections[j:], connections[j+1:])
			return connections[:len(connections)-1]
		}
	}

	return connections
}

func (i *libreswan) runPluto() error {
	logger.Info("Starting Pluto")

	args := []string{}

	if i.debug {
		args = append(args, "--stderrlog")
	}

	execCmd := exec.Command("/usr/local/bin/pluto", args...)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	var outputFile *os.File

	if i.logFile != "" {
		out, err := os.OpenFile(i.logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			return errors.Wrapf(err, "failed to open log file %s", i.logFile)
		}

		execCmd.Stdout = out
		execCmd.Stderr = out
		outputFile = out
	}

	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	cmd := command.New(execCmd)
	if err := cmd.Start(); err != nil {
		// Note - Close handles nil receiver.
		outputFile.Close()
		return errors.Wrapf(err, "error starting the Pluto process with args %v", args)
	}

	// Store FatalError locally to avoid a potential data race in the unit tests.
	fatalError := FatalError

	go func() {
		defer outputFile.Close()
		fatalError(cmd.Wait(), "Pluto exited")
	}()

	err := i.waitForControlSocket()
	if err != nil {
		return err
	}

	if i.debug {
		if err := whack("--debug", "base"); err != nil {
			return err
		}
	}

	return nil
}

func (i *libreswan) waitForControlSocket() error {
	controlSocketPath := RootDir + "/run/pluto/pluto.ctl"

	ctx, cancel := context.WithTimeout(context.TODO(), PlutoCtlSocketTimeout)
	defer cancel()

	err := wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(_ context.Context) (bool, error) {
		_, err := os.Stat(controlSocketPath)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return err == nil, err //nolint:wrapcheck // No need to wrap
	})

	return errors.Wrapf(err, "timed out waiting for the control socket at %q", controlSocketPath)
}

func (i *libreswan) Cleanup() error {
	logger.Info("Uninstalling the libreswan cable driver")

	// Stop certificate controller
	if i.certificateController != nil {
		i.certificateController.Stop()
	}

	// Close stop channel to stop other goroutines
	if i.stopCh != nil {
		close(i.stopCh)
	}

	return nil
}

// joinSubnets joins a slice of subnets into a comma-separated string
func joinSubnets(subnets []string) string {
	if len(subnets) == 0 {
		return "0.0.0.0/0"
	}
	return strings.Join(subnets, ",")
}
