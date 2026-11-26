//go:build enterprise
// SPDX-License-Identifier: LicenseRef-agentid-commercial

package agentid

import (
	"encoding/json"
	"errors"
	"os"
)

var authorityArgumentNames = map[string]bool{
	"action": true, "system": true, "resource_type": true, "resource_id_field": true,
	"stage": true, "provenance": true, "sensitivity_tier": true,
	"budget_key": true, "authority": true, "aud": true,
}

// OperatorConfig is the JSON file a platform team validates before deployment.
type OperatorConfig struct {
	Version     string        `json:"version"`
	Mode        string        `json:"mode"`
	Health      string        `json:"health"`
	Tools       []ToolMapping `json:"tools"`
	Delegations string        `json:"delegations"`
	Profile     string        `json:"profile"`
	RootKey     string        `json:"root_key"`
	SignerKey   string        `json:"signer_key"`
	StatusToken string        `json:"status_token"`
	StatusKeys  string        `json:"status_keys"`
	Approval    string        `json:"approval"`
	Fleet       string        `json:"fleet"`
}

// LoadOperatorConfig reads and validates an operator JSON config.
func LoadOperatorConfig(path string) (*OperatorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config OperatorConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

// Validate checks the shipped contract without reading referenced artifacts.
func (c *OperatorConfig) Validate() error {
	if c.Version == "" {
		c.Version = "v1"
	}
	if c.Version != "v1" {
		return errors.New("unsupported config version: " + c.Version)
	}
	if c.Mode == "" {
		c.Mode = OperatorModeEnforce
	}
	if c.Mode != OperatorModeEnforce && c.Mode != OperatorModeShadow {
		return errors.New("mode must be enforce or shadow")
	}
	if len(c.Tools) == 0 {
		return errors.New("config needs at least one tool mapping")
	}
	seen := map[string]bool{}
	for _, tool := range c.Tools {
		if tool.Name == "" || tool.Action == "" || tool.System == "" || tool.ResourceType == "" {
			return errors.New("tool mapping needs name, action, system and resource_type")
		}
		if seen[tool.Name] {
			return errors.New("duplicate tool mapping name: " + tool.Name)
		}
		seen[tool.Name] = true
		for _, arg := range tool.AllowedArgs {
			if authorityArgumentNames[arg] {
				return errors.New("authority field in allowed_args: " + arg)
			}
		}
	}
	return nil
}
