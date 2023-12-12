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

package util

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	"io"
	"os"
	"os/exec"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"sync"
)

var logger = log.Logger{Logger: logf.Log.WithName("InterfaceWatcher")}

// InterfaceWatcher represents the state for monitoring an interface
type InterfaceWatcher struct {
	InterfaceName string
	Done          chan struct{}
}

// NewInterfaceWatcher creates a new InterfaceWatcher for the given interface
func NewInterfaceWatcher(interfaceName string) (*InterfaceWatcher, error) {
	return &InterfaceWatcher{
		InterfaceName: interfaceName,
		Done:          make(chan struct{}),
	}, nil
}

// Monitor starts monitoring the rp_filter setting for the interface
func (iw *InterfaceWatcher) Monitor(wg *sync.WaitGroup) {
	logger.Infof("Interface Monitor started: %s\n")
	defer wg.Done()
	cmd := exec.Command("ip", "monitor", "link", "dev", iw.InterfaceName)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Errorf(err, "Error creating StdoutPipe:")
		close(iw.Done)
		return
	}

	err = cmd.Start()
	if err != nil {
		logger.Errorf(err, "Error starting ip monitor:")
		close(iw.Done)
		return
	}

	defer func() {
		cmd.Process.Signal(os.Interrupt) // Sending SIGINT to gracefully stop ip monitor
		cmd.Wait()
		close(iw.Done)
	}()

	for {
		select {
		case <-iw.Done:
			// Done signal received
			return
		default:
			output, err := iw.readMonitorOutput(stdout)
			if err != nil {
				logger.Errorf(err, "Error reading from ip monitor:")
				return
			}

			// Process the output as needed
			iw.processMonitorOutput(output)
		}
	}
}

func (iw *InterfaceWatcher) readMonitorOutput(reader io.Reader) (string, error) {
	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (iw *InterfaceWatcher) processMonitorOutput(output string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Process the line as needed
		if strings.Contains(line, fmt.Sprintf("%s:", iw.InterfaceName)) && strings.Contains(line, "rp_filter") {
			logger.Infof("Change detected: %s\n", line)

			// Read the current rp_filter value from the file
			rpFilterValue, err := iw.GetCurrentRpFilterSetting()
			if err != nil {
				logger.Errorf(err, "Error getting rp_filter setting for %s: %v\n", iw.InterfaceName)
				continue
			}

			// Take action: Write the value 2 back to the file if needed
			if rpFilterValue != 2 {
				if err := iw.SetRpFilterSetting(2); err != nil {
					logger.Errorf(err, "Error writing rp_filter value: %v\n")
				} else {
					logger.Infof("rp_filter changed from 2 to %d. Written back to the file.\n", rpFilterValue)
				}
			}
		}
	}
}

func (iw *InterfaceWatcher) GetCurrentRpFilterSetting() (int, error) {
	filePath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iw.InterfaceName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to read rp_filter setting for %s: %v", iw.InterfaceName)
	}

	// Parse the rp_filter value
	var rpFilterValue int
	_, err = fmt.Sscanf(string(content), "%d", &rpFilterValue)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to parse rp_filter setting for %s: %v", iw.InterfaceName)
	}

	return rpFilterValue, nil
}

func (iw *InterfaceWatcher) SetRpFilterSetting(value int) error {
	filePath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iw.InterfaceName)
	err := os.WriteFile(filePath, []byte(fmt.Sprintf("%d", value)), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to set rp_filter setting for %s: %v", iw.InterfaceName)
	}

	return nil
}
