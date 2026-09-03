package opnsense

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestFetchPFTopAndTrafficTop(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var gotPFTopBody url.Values
	mux.HandleFunc("/api/diagnostics/firewall/query_pf_top", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("pfTop method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("pfTop content type = %q, want form", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse pfTop form: %v", err)
		}
		gotPFTopBody = r.PostForm
		_, _ = w.Write([]byte(`{"rows":[{"proto":"tcp","dir":"in","src_addr":"10.0.0.1","src_port":"1234","dst_addr":"10.0.0.2","dst_port":"443","gw_addr":null,"gw_port":null,"state":"ESTABLISHED","pkts":7,"bytes":100,"rule":"r1"}],"total":1,"rowCount":1,"current":1}`))
	})

	var gotPath string
	mux.HandleFunc("/api/diagnostics/traffic/top/lan,opt1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("traffic top method = %s, want GET", r.Method)
		}
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"lan":{"status":"ok","records":[{"address":"10.0.0.1","rate_bits_in":10,"rate_bits_out":20,"rate_bits":30}]},"opt1":{"status":"timeout","records":[]}}`))
	})

	gotState, err := client.FetchPFTop()
	if err != nil {
		t.Fatalf("FetchPFTop() error: %v", err)
	}
	wantBody := url.Values{"current": {"1"}, "rowCount": {"-1"}, "searchPhrase": {""}}
	if !reflect.DeepEqual(gotPFTopBody, wantBody) {
		t.Fatalf("pfTop body = %#v, want %#v", gotPFTopBody, wantBody)
	}
	if len(gotState.States) != 1 || gotState.States[0].Bytes != 100 || gotState.States[0].Packets != 7 {
		t.Fatalf("unexpected pfTop response: %#v", gotState)
	}

	gotTraffic, err := client.FetchTrafficTop([]string{"opt1", "lan"})
	if err != nil {
		t.Fatalf("FetchTrafficTop() error: %v", err)
	}
	if gotPath != "/api/diagnostics/traffic/top/lan,opt1" {
		t.Fatalf("traffic top path = %q, want sorted interface path", gotPath)
	}
	if gotTraffic.Interfaces["lan"].Records[0].RateBits != 30 || gotTraffic.Interfaces["opt1"].Status != "timeout" {
		t.Fatalf("unexpected traffic top response: %#v", gotTraffic)
	}
}

func TestFetchTrafficTopNoInterfacesDoesNotRequest(t *testing.T) {
	called := false
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	defer server.Close()

	got, err := client.FetchTrafficTop([]string{"", "  ", ""})
	if err != nil {
		t.Fatalf("FetchTrafficTop() error: %v", err)
	}
	if called {
		t.Fatal("FetchTrafficTop made a request for an empty interface set")
	}
	if len(got.Interfaces) != 0 {
		t.Fatalf("empty traffic top response = %#v, want no interfaces", got)
	}
}

func TestFetchTrafficTopEscapesInterfacePathSegments(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/traffic/top/opt%2F1" && r.URL.EscapedPath() != "/api/diagnostics/traffic/top/opt%2F1" {
			t.Errorf("unexpected escaped traffic top path: path=%q escaped=%q", r.URL.Path, r.URL.EscapedPath())
		}
		_, _ = w.Write([]byte(`{}`))
	})
	defer server.Close()

	// OPNsense identifiers normally contain only safe characters; this test keeps
	// the URL construction from turning an unexpected identifier into a route.
	_, err := client.FetchTrafficTop([]string{"opt/1"})
	if err != nil {
		// The test server's path matching above is the assertion; a handler response
		// is otherwise valid even when no records are returned.
		t.Fatalf("FetchTrafficTop() error: %v", err)
	}
}

func TestFetchTrafficTopCanonicalizesInterfaceIdentifiers(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	var gotQuery url.Values
	mux.HandleFunc("/api/diagnostics/traffic/top/lan,opt1", func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte(`{}`))
	})

	if _, err := client.FetchTrafficTop([]string{" opt1 ", "lan", "lan"}); err != nil {
		t.Fatalf("FetchTrafficTop() error: %v", err)
	}
	if len(gotQuery) != 0 {
		t.Fatalf("unexpected query parameters: %v", gotQuery)
	}
}
