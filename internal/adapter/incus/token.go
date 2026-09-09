package incus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lxc/incus-os/incus-osd/api/seed"

	"github.com/FuturFusion/operations-center/internal/provisioning"
	"github.com/FuturFusion/operations-center/shared/api"
)

func (c Client) SystemFactoryReset(ctx context.Context, endpoint provisioning.Endpoint, allowTPMResetFailure bool, seedConfig provisioning.TokenImageSeedConfigs, providerConfig api.TokenProviderConfig) error {
	client, err := c.getClient(ctx, endpoint)
	if err != nil {
		return err
	}

	providerSeed := &seed.Provider{
		SystemProviderConfig: providerConfig.SystemProviderConfig,
		Version:              providerConfig.Version,
	}

	seedData := map[string]any{
		"applications": seedConfig.Applications,
		"incus":        seedConfig.Incus,
		"provider":     providerSeed,
	}

	if seedConfig.Network.Version != "" {
		seedData["network"] = seedConfig.Network
	}

	if seedConfig.Update.Version != "" {
		seedData["update"] = seedConfig.Update
	}

	resetData := map[string]any{
		"allow_tpm_reset_failure": allowTPMResetFailure,
		"seeds":                   seedData,
		"wipe_existing_seeds":     false,
	}

	_, _, err = client.RawQuery(http.MethodPost, "/os/1.0/system/:factory-reset", resetData, "")
	if err != nil {
		return fmt.Errorf("Factory reset on %q (%s) failed: %w", endpoint.GetName(), endpoint.GetConnectionURL(), err)
	}

	return nil
}

func (c Client) GetSecurityConfig(ctx context.Context, server provisioning.Server) (provisioning.ServerSystemSecurity, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return provisioning.ServerSystemSecurity{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/system/security", http.NoBody, "")
	if err != nil {
		return provisioning.ServerSystemSecurity{}, fmt.Errorf("Failed to get system security configuration on %q (%s): %w", server.Name, server.GetConnectionURL(), err)
	}

	var securityConfig provisioning.ServerSystemSecurity
	err = json.Unmarshal(resp.Metadata, &securityConfig)
	if err != nil {
		return provisioning.ServerSystemSecurity{}, fmt.Errorf("Unexpected response metadata while fetching system security configuration from %q (%s): %w", server.Name, server.GetConnectionURL(), err)
	}

	return securityConfig, nil
}
