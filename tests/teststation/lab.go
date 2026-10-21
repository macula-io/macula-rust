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
//	judge <i> <kind> <verdict>               judged
//
// judge sets how station i answers each registration of kind (advertise,
// unadvertise, subscribe, unsubscribe): verdict is a refusal reason
// WIRE_1_0.md section 3.5 names, "silent" to send no REGISTER_ACK, or
// "accept" to accept every registration of every kind again.
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
		answer, err := lab(t, p, fields, &stations, &realms)
		if err != nil {
			fmt.Println("error", err)
			continue
		}
		fmt.Println(answer)
	}
}

// labCommand is one line of the lab protocol, and the state it acts on.
type labCommand struct {
	t        *helperT
	p        profile.Profile
	f        []string
	stations *[]*teststation.Station
	realms   *[]teststation.Realm
}

// need says whether the line carries n fields.
func (c labCommand) need(n int) error {
	if len(c.f) < n {
		return fmt.Errorf("%s needs %d arguments", c.f[0], n-1)
	}
	return nil
}

// pick is the station the line names by its index.
func (c labCommand) pick(i int) (*teststation.Station, error) {
	if err := c.need(i + 1); err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(c.f[i])
	if err != nil || n < 0 || n >= len(*c.stations) {
		return nil, fmt.Errorf("no station %s", c.f[i])
	}
	return (*c.stations)[n], nil
}

// realm is the realm the line names by its index.
func (c labCommand) realm(i int) (teststation.Realm, error) {
	if err := c.need(i + 1); err != nil {
		return teststation.Realm{}, err
	}
	n, err := strconv.Atoi(c.f[i])
	if err != nil || n < 0 || n >= len(*c.realms) {
		return teststation.Realm{}, fmt.Errorf("no realm %s", c.f[i])
	}
	return (*c.realms)[n], nil
}

func lab(t *helperT, p profile.Profile, f []string, stations *[]*teststation.Station, realms *[]teststation.Realm) (string, error) {
	c := labCommand{t: t, p: p, f: f, stations: stations, realms: realms}
	switch f[0] {
	case "start":
		return c.start()
	case "stop":
		return c.stop()
	case "drop", "connected":
		return c.dropOrConnected()
	case "advertised":
		return c.advertised()
	case "subscribed":
		return c.subscribed()
	case "share":
		return c.share()
	case "put":
		return c.put()
	case "forge":
		return c.forge()
	case "relayed":
		return c.relayed()
	case "realm":
		return c.newRealm()
	case "impostor":
		return c.impostor()
	case "admit":
		return c.admit()
	case "judge":
		return c.judge()
	}
	return "", fmt.Errorf("unknown command %s", f[0])
}

func (c labCommand) start() (string, error) {
	if err := c.need(2); err != nil {
		return "", err
	}
	s := teststation.Start(c.t, c.p, strings.Join(c.f[1:], " "))
	*c.stations = append(*c.stations, s)
	return fmt.Sprintf("station %d %s %d %s", len(*c.stations)-1, s.Host, s.Port, hex.EncodeToString(s.NodeID[:])), nil
}

func (c labCommand) stop() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	s.Stop()
	return "stopped", nil
}

func (c labCommand) dropOrConnected() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	node, err := id32(c.f, 2)
	if err != nil {
		return "", err
	}
	if c.f[0] == "drop" {
		s.Drop(node)
		return "dropped", nil
	}
	return yes(s.Connected(node)), nil
}

func (c labCommand) advertised() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	realm, err := id32(c.f, 2)
	if err != nil {
		return "", err
	}
	if err := c.need(4); err != nil {
		return "", err
	}
	return yes(s.Advertised(realm, c.f[3])), nil
}

func (c labCommand) subscribed() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	node, err := id32(c.f, 2)
	if err != nil {
		return "", err
	}
	realm, err := id32(c.f, 3)
	if err != nil {
		return "", err
	}
	if err := c.need(5); err != nil {
		return "", err
	}
	return yes(s.Subscribed(node, realm, c.f[4])), nil
}

func (c labCommand) share() (string, error) {
	var shared []*teststation.Station
	for i := 1; i < len(c.f); i++ {
		s, err := c.pick(i)
		if err != nil {
			return "", err
		}
		shared = append(shared, s)
	}
	teststation.ShareDHT(shared...)
	return "shared", nil
}

func (c labCommand) put() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	wire, err := bytesAt(c.f, 2)
	if err != nil {
		return "", err
	}
	s.Put(wire)
	return "put", nil
}

func (c labCommand) forge() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	key, err := id32(c.f, 2)
	if err != nil {
		return "", err
	}
	wire, err := bytesAt(c.f, 3)
	if err != nil {
		return "", err
	}
	s.Forge(key, wire)
	return "forged", nil
}

func (c labCommand) relayed() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("relayed %d", s.Relayed()), nil
}

func (c labCommand) newRealm() (string, error) {
	if err := c.need(3); err != nil {
		return "", err
	}
	r := teststation.NewRealm(c.t, c.p, c.f[1], c.f[2])
	*c.realms = append(*c.realms, r)
	return fmt.Sprintf("realm %d %s %s", len(*c.realms)-1, hex.EncodeToString(r.ID[:]), hex.EncodeToString(r.RealmKey())), nil
}

func (c labCommand) impostor() (string, error) {
	if err := c.need(2); err != nil {
		return "", err
	}
	r, err := c.realm(1)
	if err != nil {
		return "", err
	}
	n, _ := strconv.Atoi(c.f[1])
	r.Key = teststation.Key(c.t, c.p, fmt.Sprintf("impostor of realm %d", n))
	*c.realms = append(*c.realms, r)
	return fmt.Sprintf("realm %d %s %s", len(*c.realms)-1, hex.EncodeToString(r.ID[:]), hex.EncodeToString(r.RealmKey())), nil
}

func (c labCommand) admit() (string, error) {
	if err := c.need(4); err != nil {
		return "", err
	}
	if _, err := c.realm(1); err != nil {
		return "", err
	}
	n, _ := strconv.Atoi(c.f[1])
	s, err := c.pick(2)
	if err != nil {
		return "", err
	}
	var nodes [][32]byte
	for i := 3; i < len(c.f); i++ {
		node, err := id32(c.f, i)
		if err != nil {
			return "", err
		}
		nodes = append(nodes, node)
	}
	(*c.realms)[n].Admit(c.t, s, nodes...)
	return "admitted", nil
}

func (c labCommand) judge() (string, error) {
	s, err := c.pick(1)
	if err != nil {
		return "", err
	}
	if err := c.need(4); err != nil {
		return "", err
	}
	s.Judge(verdict(c.f[2], c.f[3]))
	return "judged", nil
}

// verdict judges registrations of kind as given, accepting every other one;
// "accept" is nil, accepting every one.
func verdict(kind, given string) func(string) (string, bool) {
	if given == "accept" {
		return nil
	}
	return func(k string) (string, bool) {
		if k != kind {
			return "", false
		}
		if given == "silent" {
			return "", true
		}
		return given, false
	}
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
