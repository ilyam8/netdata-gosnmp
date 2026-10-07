// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"io"
	"log"
	"slices"
	"strconv"
	"testing"
)

// BenchmarkDecode measures SnmpDecodePacket on recorded packets, without a
// logger (the default) and with a logger that discards its output.
func BenchmarkDecode(b *testing.B) {
	inputs := []struct {
		name string
		in   func() []byte
	}{
		{"kyoceraResponse", kyoceraResponseBytes},
		{"ciscoGetbulkResponse", ciscoGetbulkResponseBytes},
		{"counter64Response", counter64Response},
		{"opaqueDoubleResponse", opaqueDoubleResponse},
		{"snmpv3HelloResponse", snmpv3HelloResponse},
		{"trap1", trap1},
	}
	loggers := []struct {
		name   string
		logger Logger
	}{
		{"no-logger", Logger{}},
		{"discard-logger", NewLogger(log.New(io.Discard, "", 0))},
	}

	for _, in := range inputs {
		for _, l := range loggers {
			b.Run(in.name+"/"+l.name, func(b *testing.B) {
				data := in.in()
				x := &GoSNMP{Logger: l.logger}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := x.SnmpDecodePacket(data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkEncode measures MarshalMsg on typical requests, a response, a
// trap and SNMPv3 messages.
func BenchmarkEncode(b *testing.B) {
	oids := make([]SnmpPDU, 10)
	for i := range oids {
		oids[i] = SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.10." + strconv.Itoa(i+1), Type: Null}
	}
	response, err := (&GoSNMP{}).SnmpDecodePacket(kyoceraResponseBytes())
	if err != nil {
		b.Fatal(err)
	}

	v3Request := func(flags SnmpV3MsgFlags, auth SnmpV3AuthProtocol) *SnmpPacket {
		sp := &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: "codec-auth-pass",
			AuthoritativeEngineID:    "\x80\x00\x1f\x88\x04codec-engine",
			AuthoritativeEngineBoots: 7,
			AuthoritativeEngineTime:  1234,
		}
		if auth != NoAuth {
			if err := sp.InitSecurityKeys(); err != nil {
				b.Fatal(err)
			}
		}
		return &SnmpPacket{
			Version:            Version3,
			MsgFlags:           flags,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: sp,
			PDUType:            GetRequest,
			MsgID:              4242,
			RequestID:          123456,
			Variables:          oids,
		}
	}

	packets := []struct {
		name string
		pkt  *SnmpPacket
	}{
		{"getRequest10", &SnmpPacket{Version: Version2c, Community: "public", PDUType: GetRequest, RequestID: 1, Variables: oids}},
		{"getBulkRequest", &SnmpPacket{
			Version: Version2c, Community: "public", PDUType: GetBulkRequest, RequestID: 1,
			MaxRepetitions: 25, Variables: oids[:1],
		}},
		{"kyoceraResponse", response},
		{"v1Trap", &SnmpPacket{
			Version: Version1, Community: "public", PDUType: Trap, Variables: slices.Clone(response.Variables),
			SnmpTrap: SnmpTrap{Enterprise: ".1.3.6.1.4.1.20372", AgentAddress: "192.0.2.1", GenericTrap: 6, SpecificTrap: 1},
		}},
		{"v3NoAuthGetRequest10", v3Request(NoAuthNoPriv, NoAuth)},
		{"v3AuthSHAGetRequest10", v3Request(AuthNoPriv, SHA)},
	}

	for _, p := range packets {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := p.pkt.MarshalMsg(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
