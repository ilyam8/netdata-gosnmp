// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Package netsnmp validates the gosnmp implementation against net-snmp
// either via recorded results or directly via the `libsnmp` library.
package netsnmp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// readRecording reads a base64 encoded net-snmp packet recorded by TestPDU.
func readRecording(fname string) ([]byte, error) {
	f, err := os.Open(fname)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w; run test with `-rec=true` to create missing playback files", err)
		}
		return nil, err
	}
	defer f.Close()

	out, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, f))
	if err != nil {
		return nil, err
	} else if len(out) == 0 {
		return nil, errors.New("netsnmp playback is empty")
	}

	return out, nil
}
