package opnsense

// SecurityPosture is the bounded data set used by the opt-in security-posture
// configuration snapshot. It deliberately reuses existing core endpoint
// readers, so enabling the snapshot adds no API-surface or schema contract.
// Listening sockets are not included: the socket-statistics endpoint proves
// active socket counts, but does not provide a stable listener state.
type SecurityPosture struct {
	Firmware     FirmwareStatus
	Certificates CertificateStatus
	APIKeyOwners []APIKeyOwner
}

// FetchSecurityPosture fetches the core data needed to form one posture
// snapshot. Calls are kept separate so their established decoders retain the
// narrow handling of certificate and credential-bearing wire fields.
func (c *Client) FetchSecurityPosture() (SecurityPosture, *APICallError) {
	firmware, err := c.FetchFirmwareStatus()
	if err != nil {
		return SecurityPosture{}, err
	}
	certificates, err := c.FetchCertificates()
	if err != nil {
		return SecurityPosture{}, err
	}
	owners, err := c.FetchAuthAPIKeyOwners()
	if err != nil {
		return SecurityPosture{}, err
	}
	return SecurityPosture{
		Firmware:     firmware,
		Certificates: certificates,
		APIKeyOwners: owners,
	}, nil
}
