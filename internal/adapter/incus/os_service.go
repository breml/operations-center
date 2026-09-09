package incus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	incusosapi "github.com/lxc/incus-os/incus-osd/api"

	"github.com/FuturFusion/operations-center/internal/provisioning"
)

func (c Client) GetOSService(ctx context.Context, server provisioning.Server, name string) (map[string]any, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return nil, err
	}

	nameSanitized := url.PathEscape(name)

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/"+nameSanitized, http.NoBody, "")
	if err != nil {
		return nil, fmt.Errorf("Get OS service %q on %q (%s) failed: %w", nameSanitized, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := map[string]any{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("Unexpected response metadata while fetching OS service %q configuration from %q (%s): %w", name, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceCeph(ctx context.Context, server provisioning.Server) (incusosapi.ServiceCeph, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceCeph{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/ceph", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceCeph{}, fmt.Errorf(`Get OS service "ceph" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceCeph{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceCeph{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "ceph" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceISCSI(ctx context.Context, server provisioning.Server) (incusosapi.ServiceISCSI, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceISCSI{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/iscsi", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceISCSI{}, fmt.Errorf(`Get OS service "iscsi" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceISCSI{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceISCSI{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "iscsi" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceLinstor(ctx context.Context, server provisioning.Server) (incusosapi.ServiceLinstor, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceLinstor{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/linstor", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceLinstor{}, fmt.Errorf(`Get OS service "linstor" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceLinstor{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceLinstor{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "linstor" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceLVM(ctx context.Context, server provisioning.Server) (incusosapi.ServiceLVM, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceLVM{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/lvm", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceLVM{}, fmt.Errorf(`Get OS service "lvm" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceLVM{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceLVM{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "lvm" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceMultipath(ctx context.Context, server provisioning.Server) (incusosapi.ServiceMultipath, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceMultipath{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/multipath", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceMultipath{}, fmt.Errorf(`Get OS service "multipath" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceMultipath{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceMultipath{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "multipath" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceNVME(ctx context.Context, server provisioning.Server) (incusosapi.ServiceNVME, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceNVME{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/nvme", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceNVME{}, fmt.Errorf(`Get OS service "nvme" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceNVME{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceNVME{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "nvme" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceOVN(ctx context.Context, server provisioning.Server) (incusosapi.ServiceOVN, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceOVN{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/ovn", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceOVN{}, fmt.Errorf(`Get OS service "ovn" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceOVN{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceOVN{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "ovn" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceTailscale(ctx context.Context, server provisioning.Server) (incusosapi.ServiceTailscale, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceTailscale{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/tailscale", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceTailscale{}, fmt.Errorf(`Get OS service "tailscale" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceTailscale{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceTailscale{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "tailscale" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) GetOSServiceUSBIP(ctx context.Context, server provisioning.Server) (incusosapi.ServiceUSBIP, error) {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return incusosapi.ServiceUSBIP{}, err
	}

	resp, _, err := client.RawQuery(http.MethodGet, "/os/1.0/services/usbip", http.NoBody, "")
	if err != nil {
		return incusosapi.ServiceUSBIP{}, fmt.Errorf(`Get OS service "usbip" on %q (%s) failed: %w`, server.Name, server.ConnectionURL, err)
	}

	serviceConfig := incusosapi.ServiceUSBIP{}

	err = json.Unmarshal(resp.Metadata, &serviceConfig)
	if err != nil {
		return incusosapi.ServiceUSBIP{}, fmt.Errorf(`Unexpected response metadata while fetching OS service "usbip" configuration from %q (%s): %w`, server.Name, server.GetConnectionURL(), err)
	}

	return serviceConfig, nil
}

func (c Client) UpdateOSService(ctx context.Context, server provisioning.Server, name string, config any) error {
	client, err := c.getClient(ctx, server)
	if err != nil {
		return err
	}

	nameSanitized := url.PathEscape(name)

	switch t := config.(type) {
	case map[string]any:
		_, ok := t["config"]
		if !ok {
			config = map[string]any{
				"config": config,
			}
		}
	}

	_, _, err = client.RawQuery(http.MethodPut, "/os/1.0/services/"+nameSanitized, config, "")
	if err != nil {
		return fmt.Errorf("Update OS service %q on %q (%s) failed: %w", nameSanitized, server.Name, server.ConnectionURL, err)
	}

	return nil
}
