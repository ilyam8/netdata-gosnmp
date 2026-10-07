// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// The purpose of these tests is to validate gosnmp's public APIs.
//
// IMPORTANT: If you're modifying _any_ existing code in this file, you
// should be asking yourself about API compatibility!

package gosnmp_test // force external view

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/netdata/gosnmp"
)

func TestAPIConfigTypes(_ *testing.T) {
	g := &gosnmp.GoSNMP{}
	g.Target = ""
	g.Port = 0
	g.Community = ""
	g.Version = gosnmp.Version1
	g.Version = gosnmp.Version2c
	g.Timeout = time.Duration(0)
	g.Retries = 0
	g.MaxOids = 0
	g.MaxRepetitions = 0
	g.NonRepeaters = 0
	g.Logger = gosnmp.NewLogger(log.New(io.Discard, "", 0))
	var c net.Conn = g.Conn
	_ = c
}

func TestAPIDefault(_ *testing.T) {
	var g *gosnmp.GoSNMP = gosnmp.Default
	_ = g
}

func TestAPIConnectMethodSignature(_ *testing.T) {
	var f func() error = gosnmp.Default.Connect
	_ = f
}

func TestAPIGetMethodSignature(_ *testing.T) {
	var f func([]string) (*gosnmp.SnmpPacket, error) = gosnmp.Default.Get
	_ = f
}

func TestAPISetMethodSignature(_ *testing.T) {
	var f func([]gosnmp.SnmpPDU) (*gosnmp.SnmpPacket, error) = gosnmp.Default.Set
	_ = f
}

func TestAPIGetNextMethodSignature(_ *testing.T) {
	var f func([]string) (*gosnmp.SnmpPacket, error) = gosnmp.Default.GetNext
	_ = f
}

func TestAPIBulkWalkMethodSignature(_ *testing.T) {
	var f func(string, gosnmp.WalkFunc) error = gosnmp.Default.BulkWalk
	_ = f
}

func TestAPIBulkWalkAllMethodSignature(_ *testing.T) {
	var f func(string) ([]gosnmp.SnmpPDU, error) = gosnmp.Default.BulkWalkAll
	_ = f
}

func TestAPIWalkMethodSignature(_ *testing.T) {
	var f func(string, gosnmp.WalkFunc) error = gosnmp.Default.Walk
	_ = f
}

func TestAPIWalkAllMethodSignature(_ *testing.T) {
	var f func(string) ([]gosnmp.SnmpPDU, error) = gosnmp.Default.WalkAll
	_ = f
}

func TestAPIWalkFuncSignature(_ *testing.T) {
	var f gosnmp.WalkFunc = func(_ gosnmp.SnmpPDU) (err error) { return err }
	_ = f
}
