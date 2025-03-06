package executor

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	"github.com/Nishantbhagat57/dnstake/internal/errors"
	"github.com/Nishantbhagat57/dnstake/internal/option"
	"github.com/Nishantbhagat57/dnstake/pkg/dnstake"
	"github.com/Nishantbhagat57/dnstake/pkg/fingerprint"
)

// New to execute target hostname
func New(opt *option.Options, hostname string) {
	var out = ""

	vuln, DNS, takeover_type, targetHost, err := exec(hostname)
	if err != nil {
		gologger.Error().Msgf("%s: %s", hostname, err.Error())
	}

	if vuln {
		if !opt.Silent {
			out += fmt.Sprintf("[%s] ", aurora.Green("VLN"))
		}

		out += hostname

		if !opt.Silent {
			if takeover_type == "CNAME" {
				out += fmt.Sprintf(" (%s to %s)", aurora.BrightMagenta("CNAME Takeover"), aurora.BrightCyan(targetHost))
			} else {
				out += fmt.Sprintf(" (%s)", aurora.Cyan(DNS.Provider))
			}
		}

		if !opt.Silent && takeover_type == "NS" {
			for _, status := range DNS.Status {
				switch status {
				case 2:
					out += fmt.Sprintf(" (%s)", aurora.Magenta("Edge Case"))
				case 3:
					out += fmt.Sprintf(" (%s)", aurora.Yellow("$"))
				}
			}
		}

		if opt.Output != "" {
			writeToFile(hostname, opt.Output)
		}
	}

	if out != "" {
		fmt.Println(out)
	}
}

func writeToFile(data, output string) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	wrt := bufio.NewWriter(file)

	_, err = wrt.WriteString(data + "\n")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}

	wrt.Flush()
	file.Close()
}

// Direct CNAME check function
func checkCNAME(client *retryabledns.Client, hostname string) (bool, string, error) {
	res, err := dnstake.Resolve(client, hostname, 5) // 5 = CNAME
	if err != nil {
		return false, "", err
	}

	if len(res.CNAME) > 0 {
		cnameTarget := res.CNAME[0]
		gologger.Debug().Msgf("Found CNAME for %s pointing to %s", hostname, cnameTarget)
		
		// Check if the CNAME target is vulnerable
		targetRes, err := dnstake.Resolve(client, cnameTarget, 1) // 1 = A record
		if err != nil {
			gologger.Debug().Msgf("Error resolving CNAME target %s: %v", cnameTarget, err)
			return false, cnameTarget, nil
		}
		
		if targetRes.StatusCode == "SERVFAIL" || targetRes.StatusCode == "REFUSED" {
			gologger.Debug().Msgf("CNAME target %s returned %s - VULNERABLE!", cnameTarget, targetRes.StatusCode)
			return true, cnameTarget, nil
		}
		
		// If first level CNAME is not vulnerable, check if it points to another CNAME
		return checkCNAME(client, cnameTarget)
	}
	
	return false, "", nil
}

func exec(hostname string) (bool, fingerprint.DNS, string, string, error) {
	var (
		vuln         bool
		DNS          = fingerprint.DNS{}
		takeover_type = ""
		targetHost   = ""
	)

	client, clientErr := retryabledns.New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 3)
	if clientErr != nil {
		return vuln, DNS, takeover_type, targetHost, fmt.Errorf("failed to create DNS client: %v", clientErr)
	}

	// First check for CNAME takeovers - they're more common
	cnameVuln, cnameTarget, cnameErr := checkCNAME(client, hostname)
	if cnameErr != nil {
		gologger.Debug().Msgf("CNAME check error for %s: %v", hostname, cnameErr)
	} else if cnameVuln && cnameTarget != "" {
		cnameDNS := fingerprint.DNS{
			Provider: "CNAME Takeover",
			Status:   []int{1}, // Mark as vulnerable
		}
		return true, cnameDNS, "CNAME", cnameTarget, nil
	}
	
	// Then check for NS takeovers
	q1, err := dnstake.Resolve(client, hostname, 2) // 2 = NS records
	if err != nil {
		// If we already checked CNAME and found nothing, report appropriate error
		if strings.Contains(err.Error(), "no record found") || strings.Contains(err.Error(), "NXDOMAIN") {
			return vuln, DNS, takeover_type, targetHost, fmt.Errorf("%s", errors.ErrNoNSRec)
		}
		return vuln, DNS, takeover_type, targetHost, fmt.Errorf("%s: %v", errors.ErrResolve, err)
	}

	// If no NS records, report that
	if len(q1.NS) < 1 {
		return vuln, DNS, takeover_type, targetHost, fmt.Errorf("%s", errors.ErrNoNSRec)
	}

	// Check if the NS records match any known providers
	fgp, rec, err := fingerprint.Check(q1.NS)
	if err != nil {
		return vuln, fgp, takeover_type, targetHost, fmt.Errorf("%s (%s)", errors.ErrPattern, err.Error())
	}

	if rec == "" {
		return false, fgp, takeover_type, targetHost, fmt.Errorf("%s", errors.ErrFinger)
	}

	// Check if the provider is known to be not vulnerable
	if _, m := find(fgp.Status, 0); m {
		return vuln, DNS, takeover_type, targetHost, fmt.Errorf("%s", errors.ErrNotVuln)
	}

	// Verify if the NS records respond with SERVFAIL/REFUSED
	q2, err := dnstake.Resolve(client, rec, 1)
	if err != nil {
		return vuln, DNS, takeover_type, targetHost, fmt.Errorf("%s (%s)", errors.ErrResolve, rec)
	}

	vuln, err = dnstake.Verify(q2.A, hostname)
	if err != nil {
		return vuln, DNS, takeover_type, targetHost, fmt.Errorf("%s (%s)", errors.ErrVerify, err.Error())
	}

	if vuln {
		return vuln, fgp, "NS", rec, nil
	}

	return false, fgp, takeover_type, targetHost, fmt.Errorf("%s", errors.ErrUnknown)
}


