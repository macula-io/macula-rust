package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// runLab starts stations and realms as commands ask, each named by its index
// in the order it was started, and answers each command with one line:
//
//	start <name>                             station <i> <host> <port> <node_id hex>
//	stop <i>                                 stopped
//	drop <i> <node hex>                      dropped
//	connected <i> <node hex>                 yes | no
//	advertised <i> <realm hex> <procedure>   yes | no
//	subscribed <i> <node hex> <realm hex> <topic>   yes | no
//	share <i> <j> ...                        shared
//	put <i> <wire hex>                       put
//	forge <i> <key hex> <wire hex>           forged
//	relayed <i>                              relayed <n>
//	realm <name> <org>                       realm <r> <realm_id hex> <realm_key hex>
//	impostor <r>                             realm <r2> <realm_id hex> <realm_key hex>
//	admit <r> <i> <node hex> ...             admitted
//
// An impostor of realm r has its realm_id and org and another realm key, as a
// node claiming the realm without its key would sign.
//
// A command it cannot follow is answered "error <why>".
func runLab(t *helperT, p profile.Profile) {
	var stations []*teststation.Station
	var realms []teststation.Realm
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 4<<20)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		if len(fields) == 0 {
			continue
		}
		station := func(i int) *teststation.Station {
			n, err := strconv.Atoi(fields[i])
			if err != nil || n < 0 || n >= len(stations) {
				return nil
			}
			return stations[n]
		}
		answer, err := lab(t, p, fields, station, &stations, &realms)
		if err != nil {
			fmt.Println("error", err)
			continue
		}
		fmt.Println(answer)
	}
}

func lab(t *helperT, p profile.Profile, f []string, station func(int) *teststation.Station,
	stations *[]*teststation.Station, realms *[]teststation.Realm) (string, error) {
	need := func(n int) error {
		if len(f) < n {
			return fmt.Errorf("%s needs %d arguments", f[0], n-1)
		}
		return nil
	}
	pick := func(i int) (*teststation.Station, error) {
		if err := need(i + 1); err != nil {
			return nil, err
		}
		if s := station(i); s != nil {
			return s, nil
		}
		return nil, fmt.Errorf("no station %s", f[i])
	}
	switch f[0] {
	case "start":
		if err := need(2); err != nil {
			return "", err
		}
		s := teststation.Start(t, p, strings.Join(f[1:], " "))
		*stations = append(*stations, s)
		return fmt.Sprintf("station %d %s %d %s", len(*stations)-1, s.Host, s.Port, hex.EncodeToString(s.NodeID[:])), nil
	case "stop":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		s.Stop()
		return "stopped", nil
	case "drop", "connected":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		node, err := id32(f, 2)
		if err != nil {
			return "", err
		}
		if f[0] == "drop" {
			s.Drop(node)
			return "dropped", nil
		}
		return yes(s.Connected(node)), nil
	case "advertised":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		realm, err := id32(f, 2)
		if err != nil {
			return "", err
		}
		if err := need(4); err != nil {
			return "", err
		}
		return yes(s.Advertised(realm, f[3])), nil
	case "subscribed":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		node, err := id32(f, 2)
		if err != nil {
			return "", err
		}
		realm, err := id32(f, 3)
		if err != nil {
			return "", err
		}
		if err := need(5); err != nil {
			return "", err
		}
		return yes(s.Subscribed(node, realm, f[4])), nil
	case "share":
		var shared []*teststation.Station
		for i := 1; i < len(f); i++ {
			s, err := pick(i)
			if err != nil {
				return "", err
			}
			shared = append(shared, s)
		}
		teststation.ShareDHT(shared...)
		return "shared", nil
	case "put":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		wire, err := bytesAt(f, 2)
		if err != nil {
			return "", err
		}
		s.Put(wire)
		return "put", nil
	case "forge":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		key, err := id32(f, 2)
		if err != nil {
			return "", err
		}
		wire, err := bytesAt(f, 3)
		if err != nil {
			return "", err
		}
		s.Forge(key, wire)
		return "forged", nil
	case "relayed":
		s, err := pick(1)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("relayed %d", s.Relayed()), nil
	case "realm":
		if err := need(3); err != nil {
			return "", err
		}
		r := teststation.NewRealm(t, p, f[1], f[2])
		*realms = append(*realms, r)
		return fmt.Sprintf("realm %d %s %s", len(*realms)-1, hex.EncodeToString(r.ID[:]), hex.EncodeToString(r.RealmKey())), nil
	case "impostor":
		if err := need(2); err != nil {
			return "", err
		}
		n, err := strconv.Atoi(f[1])
		if err != nil || n < 0 || n >= len(*realms) {
			return "", fmt.Errorf("no realm %s", f[1])
		}
		r := (*realms)[n]
		r.Key = teststation.Key(t, p, fmt.Sprintf("impostor of realm %d", n))
		*realms = append(*realms, r)
		return fmt.Sprintf("realm %d %s %s", len(*realms)-1, hex.EncodeToString(r.ID[:]), hex.EncodeToString(r.RealmKey())), nil
	case "admit":
		if err := need(4); err != nil {
			return "", err
		}
		n, err := strconv.Atoi(f[1])
		if err != nil || n < 0 || n >= len(*realms) {
			return "", fmt.Errorf("no realm %s", f[1])
		}
		s, err := pick(2)
		if err != nil {
			return "", err
		}
		var nodes [][32]byte
		for i := 3; i < len(f); i++ {
			node, err := id32(f, i)
			if err != nil {
				return "", err
			}
			nodes = append(nodes, node)
		}
		(*realms)[n].Admit(t, s, nodes...)
		return "admitted", nil
	}
	return "", fmt.Errorf("unknown command %s", f[0])
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func bytesAt(f []string, i int) ([]byte, error) {
	if len(f) <= i {
		return nil, fmt.Errorf("%s needs argument %d", f[0], i)
	}
	return hex.DecodeString(f[i])
}

func id32(f []string, i int) ([32]byte, error) {
	var out [32]byte
	raw, err := bytesAt(f, i)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("argument %d is not 32 bytes", i)
	}
	copy(out[:], raw)
	return out, nil
}
