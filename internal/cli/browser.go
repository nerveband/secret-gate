package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/nerveband/secret-gate/internal/core"
)

func init() {
	usageText["browser fill"] = `Usage: secret-gate browser fill --item <name> --cdp <endpoint> --field '<field>[:<format>]=<css selector>' ...
                              [--vault <vault>] [--page-url <substring>] [--target <id>] [--frame-url <substring>]

Type approved, cached values into form fields of a browser tab. Secret Gate
opens its own DevTools session to the tab (loopback only), so values go
from Secret Gate to the page and never through the agent. The output lists
which selectors were filled, never the values. Card numbers, CVVs, and PINs
are filled only into https pages.

--field is repeatable. The selector is searched in the page, its
same-origin frames, and open shadow roots; for a cross-origin payment
iframe pass --frame-url with a substring of the iframe URL. Expiry dates
take a format suffix: MM, M, YY, YYYY, MM/YY, MM/YYYY, MMYY, MM-YY, YYYY-MM.
Menus (<select>) pick the option whose value or text matches.

Do not snapshot or screenshot the page after filling card fields: the
number is then visible in the page. Take element refs before filling and
click the pay button by ref.

Example (approve first: request submit --fields number,cvv,expiry,cardholder --purpose ...):
  secret-gate browser fill --item "Visa travel" --cdp "$(agent-browser get cdp-url)" --page-url aa.com \
    --field 'cardholder=#nameOnCard' --field 'number=#cardNumber' \
    --field 'expiry:MM=#expMonth' --field 'expiry:YYYY=#expYear' --field 'cvv=#securityCode'`
}

// repeatedFlag collects every value of a repeatable string flag.
type repeatedFlag []string

func (r *repeatedFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error { *r = append(*r, v); return nil }

func (a *App) runBrowser(args []string) int {
	if len(args) == 0 || args[0] != "fill" {
		got := ""
		if len(args) > 0 {
			got = fmt.Sprintf(" (got %q)", args[0])
		}
		return a.fail("browser", "usage", "browser requires the subcommand fill"+got, "run: secret-gate browser fill --help")
	}
	const command = "browser fill"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "approved, cached item")
	vault := fs.String("vault", "", "vault name")
	cdp := fs.String("cdp", "", "Chrome DevTools endpoint on this machine (ws:// URL, http://host:port, or port)")
	pageURL := fs.String("page-url", "", "substring of the tab URL")
	target := fs.String("target", "", "DevTools target ID of the tab")
	frameURL := fs.String("frame-url", "", "substring of a cross-origin iframe URL (payment iframes)")
	var specs repeatedFlag
	fs.Var(&specs, "field", "repeatable: <field>[:<format>]=<css selector>")
	if code, done := a.parse(fs, command, args[1:]); done {
		return code
	}
	if *item == "" || *cdp == "" {
		return a.fail(command, "usage", "--item and --cdp are required", `example: --cdp "$(agent-browser get cdp-url)"`)
	}
	fields := make([]core.FillSpec, 0, len(specs))
	for _, s := range specs {
		spec, err := core.ParseFillSpec(s)
		if err != nil {
			return a.failErr(command, err)
		}
		fields = append(fields, spec)
	}
	out, err := a.Service.BrowserFill(context.Background(), core.BrowserFillRequest{
		SecretName: *item, Vault: *vault,
		Target:   core.PasskeyTarget{Endpoint: *cdp, PageURL: *pageURL, TargetID: *target},
		FrameURL: *frameURL, Fields: fields,
	})
	if err != nil {
		return a.failErr(command, err)
	}
	exit := ExitOK
	if out.Filled != len(out.Results) {
		exit = ExitFailure
	}
	return a.okWithExit(command, out, &Meta{Visibility: VisibilityProcessOnly, Cache: "hit"}, exit)
}
