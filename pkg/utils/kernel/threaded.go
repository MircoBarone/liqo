// Copyright 2019-2026 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kernel

import (
	"fmt"
	"os"
	"path/filepath"
    "golang.org/x/sys/unix"
	"k8s.io/klog/v2"
    "time"
)

const threadedFilePattern = "/sys/class/net/liqo-tunnel*/threaded"

// Enable the threaded mode in all wireguard interfaces.
// It writes 1 to /sys/class/net/liqo-tunnel*/threaded.
func EnableWireguardThreadedMode() error {
    matches, err := filepath.Glob(threadedFilePattern)
    if err != nil {
        return fmt.Errorf("failed to search for wireguard threaded files: %w", err)
    }
    if len(matches) == 0 {
        return nil
    }

    remountSysfsRW()
    defer remountSysfsRO()

    for _, path := range matches {
        ifaceName := filepath.Base(filepath.Dir(path))
        if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
            return fmt.Errorf("failed to enable threaded mode for %s: %v", ifaceName, err)
        }
        
        klog.Infof("Threaded mode enabled for interface %s", ifaceName)
    }
    
    return nil
}

// remountSysfsRW remounts sysfs as read/write, retrying a few times if busy.
func remountSysfsRW()  {
    
    for {
        err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_REMOUNT, "rw")
        if err == nil {
            break
        }
        klog.Infof("Failed to remount /sys as read-write (resource busy?), retrying in 100ms...: %v", err)
        time.Sleep(100 * time.Millisecond)
    }
    
}

// remountSysfsRO remounts sysfs as read-only for security, retrying a few times if busy.
func remountSysfsRO() {
    for {
        err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_REMOUNT|unix.MS_RDONLY, "")
        if err == nil {
            klog.Info("Successfully remounted /sys as read-only")
            break
        }

        klog.Infof("Failed to remount /sys as read-only (resource busy?), retrying in 100ms...: %v", err)
        time.Sleep(100 * time.Millisecond)
    }
}