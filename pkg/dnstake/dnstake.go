package dnstake

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
)

// Verify if the response is not NOERROR
func Verify(IPs []string, hostname string) (bool, error) {
	retries := 3

	if len(IPs) < 1 {
		return false, nil
	}

	for i, k := range IPs {
		if k == "" {
			continue
		}

		IPs[i] += ":53"
	}

	if len(IPs) > retries {
		retries = len(IPs)
	}

	client, clientErr := retryabledns.New(IPs, retries)
	if clientErr != nil {
		return false, clientErr
	}
	res, err := Resolve(client, hostname, 1)

	if err != nil {
		return false, err
	}

	if res.StatusCode == "SERVFAIL" || res.StatusCode == "REFUSED" {
		return true, nil
	}

	return false, nil
}

// Directly check if a domain is vulnerable via CNAME
func VerifyCNAME(client *retryabledns.Client, hostname string) (bool, string, error) {
	// Get CNAME record
	res, err := Resolve(client, hostname, 5) // Type 5 is CNAME
	if err != nil {
		gologger.Debug().Msgf("Error getting CNAME for %s: %v", hostname, err)
		return false, "", err
	}

	// If there's a CNAME record
	if len(res.CNAME) > 0 {
		target := res.CNAME[0]
		gologger.Debug().Msgf("Found CNAME %s -> %s", hostname, target)

		// Check if target is resolvable
		targetRes, err := Resolve(client, target, 1) // Type 1 is A record
		if err != nil {
			gologger.Debug().Msgf("Error resolving CNAME target %s: %v", target, err)
			// If we can't resolve, it might be vulnerable
			return true, target, nil
		}

		// If target returns SERVFAIL or REFUSED, it's vulnerable
		if targetRes.StatusCode == "SERVFAIL" || targetRes.StatusCode == "REFUSED" {
			gologger.Debug().Msgf("CNAME target %s returned %s - VULNERABLE!", target, targetRes.StatusCode)
			return true, target, nil
		}

		gologger.Debug().Msgf("CNAME target %s returned %s - not vulnerable", target, targetRes.StatusCode)
		return false, target, nil
	}

	return false, "", nil
}

