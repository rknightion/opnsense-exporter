package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// UpstreamEndpoint is one API endpoint as extracted from OPNsense source by
// tools/opnsense_api_contract/extract.py.
type UpstreamEndpoint struct {
	Module     string   `json:"module"`
	Controller string   `json:"controller"`
	Command    string   `json:"command"`
	Methods    []string `json:"methods"`
	Path       string   `json:"path"`
}

// loadUpstream reads a JSON array produced by extract.py.
func loadUpstream(path string) ([]UpstreamEndpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read upstream file: %w", err)
	}
	var out []UpstreamEndpoint
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse upstream JSON: %w", err)
	}
	return out, nil
}
