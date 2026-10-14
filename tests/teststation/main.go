// Command teststation runs in-process macula 12 stations for the Rust
// tests, in one of two modes.
//
// By default: two stations sharing one DHT, and a test realm with one org.
// It prints one JSON line, {stations: [{host, port, node_id}], realm_id,
// realm_key, org}, then reads commands on stdin until it closes:
//
//	admit <node_id hex>   the org delegates its procedures to that node
//	grant <node_id hex>   the org's group_keys grant for that node, a UCAN
//	                      over mri:org:<realm_name>/<org> living an hour
//	relayed               how many streams the stations relay now
//
// With a second argument "lab": no stations yet, and the commands in lab.go,
// which start and shape stations and realms one by one.
//
// Either mode answers each command with one line, and exits when stdin
// closes.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
	"github.com/macula-io/macula-go/ucan"
)

// helperT is teststation.T for a process rather than a test: failures go to
// stderr, a fatal one ends the process, and cleanups run at exit.
type helperT struct{ cleanups []func() }

func (t *helperT) Helper() {}
func (t *helperT) Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "teststation: "+format+"\n", args...)
}
func (t *helperT) Fatalf(format string, args ...any) {
	t.Errorf(format, args...)
	t.run()
	os.Exit(1)
}
func (t *helperT) Cleanup(f func()) { t.cleanups = append(t.cleanups, f) }
func (t *helperT) run() {
	for i := len(t.cleanups) - 1; i >= 0; i-- {
		t.cleanups[i]()
	}
}

func main() {
	t := &helperT{}
	defer t.run()
	p := profile.PQPure
	if len(os.Args) > 1 {
		parsed, err := profile.Parse(os.Args[1])
		if err != nil {
			t.Fatalf("%v", err)
		}
		p = parsed
	}
	if len(os.Args) > 2 && os.Args[2] == "lab" {
		runLab(t, p)
		return
	}
	stations := []*teststation.Station{teststation.Start(t, p, "rust a"), teststation.Start(t, p, "rust b")}
	teststation.ShareDHT(stations...)
	realm := teststation.NewRealm(t, p, "macula-rust.tests", "mcl-rust")
	type station struct {
		Host   string `json:"host"`
		Port   uint16 `json:"port"`
		NodeID string `json:"node_id"`
	}
	out := struct {
		Stations  []station `json:"stations"`
		RealmName string    `json:"realm_name"`
		RealmID   string    `json:"realm_id"`
		RealmKey  string    `json:"realm_key"`
		Org       string    `json:"org"`
		OrgKeyID  string    `json:"org_key_id"`
	}{RealmName: realm.Name, RealmID: hex.EncodeToString(realm.ID[:]),
		RealmKey: hex.EncodeToString(realm.RealmKey()), Org: realm.Org}
	orgKeyID := identity.KeyIDOf(realm.OrgKey.PublicKey(), p)
	out.OrgKeyID = hex.EncodeToString(orgKeyID[:])
	for _, s := range stations {
		out.Stations = append(out.Stations, station{Host: s.Host, Port: s.Port, NodeID: hex.EncodeToString(s.NodeID[:])})
	}
	line, _ := json.Marshal(out)
	fmt.Println(string(line))
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		switch {
		case len(fields) == 2 && fields[0] == "admit":
			raw, err := hex.DecodeString(fields[1])
			if err != nil || len(raw) != 32 {
				fmt.Println("error bad node_id")
				continue
			}
			var node [32]byte
			copy(node[:], raw)
			realm.Admit(t, stations[0], node)
			fmt.Println("admitted", fields[1])
		case len(fields) == 2 && fields[0] == "grant":
			raw, err := hex.DecodeString(fields[1])
			if err != nil || len(raw) != 32 {
				fmt.Println("error bad node_id")
				continue
			}
			token, err := ucan.Create(realm.OrgKey, [32]byte(raw), []ucan.Capability{
				{With: "mri:org:" + realm.Name + "/" + realm.Org, Can: "group_keys"}}, ucan.Options{Exp: time.Now().Unix() + 3600})
			if err != nil {
				fmt.Println("error", err)
				continue
			}
			fmt.Println("grant", string(token))
		case len(fields) == 1 && fields[0] == "relayed":
			fmt.Println("relayed", stations[0].Relayed()+stations[1].Relayed())
		default:
			fmt.Println("error unknown command")
		}
	}
}
