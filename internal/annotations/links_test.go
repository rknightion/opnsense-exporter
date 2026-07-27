package annotations

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestContextLinkCarriesInstanceAndAWindowAroundTheEvent(t *testing.T) {
	at := time.Unix(1785168482, 0)
	link := contextLink("https://example.grafana.net/", "fw1", at)

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not a URL: %v", err)
	}
	if parsed.Host != "example.grafana.net" {
		t.Fatalf("host = %q, want the configured Grafana host", parsed.Host)
	}
	if want := "/d/" + DashboardUID; parsed.Path != want {
		t.Fatalf("path = %q, want %q", parsed.Path, want)
	}

	q := parsed.Query()
	if got := q.Get(InstanceVar); got != "fw1" {
		t.Fatalf("%s = %q, want the event's own instance", InstanceVar, got)
	}
	// The window must BRACKET the event, not start at it: an annotation opened at
	// exactly the event instant shows the aftermath and none of the run-up, which is
	// the comparison an operator actually needs.
	from, to := q.Get("from"), q.Get("to")
	if from == "" || to == "" {
		t.Fatalf("link drops the time range: from=%q to=%q", from, to)
	}
	wantFrom := at.Add(-linkWindow).UnixMilli()
	wantTo := at.Add(linkWindow).UnixMilli()
	if from != strconv.FormatInt(wantFrom, 10) || to != strconv.FormatInt(wantTo, 10) {
		t.Fatalf("window = [%s,%s], want [%d,%d]", from, to, wantFrom, wantTo)
	}
}

func TestContextLinkIsOmittedWhenItCouldNotResolve(t *testing.T) {
	// No instance means no scoped link, and a link with an empty variable is worse
	// than none: it silently lands on whatever the dashboard defaults to.
	if got := contextLink("https://example.grafana.net", "", time.Unix(1, 0)); got != "" {
		t.Fatalf("link with no instance = %q, want empty", got)
	}
	for _, base := range []string{"", "   ", "not a url", "ftp://example.net"} {
		if got := contextLink(base, "fw1", time.Unix(1, 0)); got != "" {
			t.Fatalf("link for base %q = %q, want empty", base, got)
		}
	}
}

func TestWithLinkAppendsMarkdownAndLeavesTextIntactWithoutOne(t *testing.T) {
	at := time.Unix(1785168482, 0)
	event := Event{Kind: "reboot", Text: "OPNsense rebooted", At: at,
		Tags: []string{BaseTag, "reboot", "instance:fw1"}}

	linked := withLink(event, "https://example.grafana.net")
	if !strings.HasPrefix(linked, "OPNsense rebooted") {
		t.Fatalf("linked text lost the event text: %q", linked)
	}
	if !strings.Contains(linked, "](https://example.grafana.net/d/"+DashboardUID) {
		t.Fatalf("linked text carries no markdown dashboard link: %q", linked)
	}
	if !strings.Contains(linked, "var-opnsense_instance=fw1") {
		t.Fatalf("linked text drops the instance: %q", linked)
	}

	// A deployment whose Grafana URL is unusable still gets the annotation, without
	// a dangling markdown link in the tooltip.
	if got := withLink(event, "nonsense"); got != event.Text {
		t.Fatalf("unlinked text = %q, want %q", got, event.Text)
	}
}

func TestPostedAnnotationCarriesTheLinkedText(t *testing.T) {
	c := newClient(Config{URL: "https://example.grafana.net", Token: "t"})
	event := Event{Kind: "config_change", Text: "OPNsense configuration changed",
		At: time.Unix(1785168482, 0), Tags: []string{BaseTag, "config_change", "instance:fw1"}}

	got := c.payloadFor(event).Text
	if !strings.Contains(got, "/d/"+DashboardUID) {
		t.Fatalf("posted text has no dashboard link: %q", got)
	}
	if !strings.HasPrefix(got, event.Text) {
		t.Fatalf("posted text = %q, want it to start with %q", got, event.Text)
	}
}
