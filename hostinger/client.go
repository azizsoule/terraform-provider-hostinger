package hostinger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var ErrNotFound = errors.New("not found")

// HostingerClient is a minimal API client for Hostinger's public API
type HostingerClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
	Version    string
}

// NewHostingerClient initializes a new API client with the given token
func NewHostingerClient(token, version string) *HostingerClient {
	return &HostingerClient{
		BaseURL:    "https://developers.hostinger.com",
		HTTPClient: &http.Client{},
		Token:      token,
		Version:    version,
	}
}

type PaymentMethod struct {
	ID        int  `json:"id"`
	IsDefault bool `json:"is_default"`
}

func (client *HostingerClient) addStandardHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+client.Token)
	req.Header.Set("User-Agent", "terraform-provider-hostinger/0.1.18")
	req.Header.Set("Content-Type", "application/json")
}

func (c *HostingerClient) GetDefaultPaymentMethod() (int, error) {
	url := c.BaseURL + "/api/billing/v1/payment-methods"

	req, _ := http.NewRequest("GET", url, nil)
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("failed to list payment methods (HTTP %d): %s", resp.StatusCode, msg)
	}

	var methods []PaymentMethod
	if err := json.NewDecoder(resp.Body).Decode(&methods); err != nil {
		return 0, err
	}

	for _, pm := range methods {
		if pm.IsDefault {
			return pm.ID, nil
		}
	}

	return 0, fmt.Errorf("no default payment method found")
}

func (c *HostingerClient) GetSubscriptionIDByVMID(vmID int) (string, error) {
	vm, err := c.GetVirtualMachine(vmID)
	if err != nil {
		return "", err
	}

	if vm.SubscriptionID == "" {
		return "", fmt.Errorf("subscription_id is empty for VPS ID %d", vmID)
	}

	return vm.SubscriptionID, nil
}

type Subscription struct {
	ID      string `json:"id"`
	Product struct {
		Type       string `json:"type"`
		ResourceID int    `json:"resource_id"`
	} `json:"product"`
}

func (c *HostingerClient) CancelSubscription(subscriptionID string) error {
	url := fmt.Sprintf("%s/api/billing/v1/subscriptions/%s", c.BaseURL, subscriptionID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create cancel subscription request: %w", err)
	}

	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to cancel subscription %s (HTTP %d): %s", subscriptionID, resp.StatusCode, string(msg))
	}

	return nil
}

// SetupRequest defines the payload to set up (activate) a new VPS.
type SetupRequest struct {
	DataCenterID        int     `json:"data_center_id"`
	TemplateID          int     `json:"template_id"`
	Password            *string `json:"password,omitempty"`
	Hostname            *string `json:"hostname,omitempty"`
	PostInstallScriptId *int    `json:"post_install_script_id,omitempty"`
}

// PurchaseVMRequest defines the payload to purchase a new VPS.
type PurchaseVMRequest struct {
	ItemID          string       `json:"item_id"`
	Setup           SetupRequest `json:"setup"`
	PaymentMethodID *int         `json:"payment_method_id,omitempty"`
}

// BillingAddress represents the billing address from an order
type BillingAddress struct {
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Company   *string `json:"company"`
	Address1  *string `json:"address_1"`
	Address2  *string `json:"address_2"`
	City      *string `json:"city"`
	State     *string `json:"state"`
	Zip       *string `json:"zip"`
	Country   string  `json:"country"`
	Phone     *string `json:"phone"`
	Email     string  `json:"email"`
}

// Order represents the order details from a purchase
type Order struct {
	ID             int            `json:"id"`
	SubscriptionID string         `json:"subscription_id"`
	Status         string         `json:"status"`
	Currency       string         `json:"currency"`
	Subtotal       int            `json:"subtotal"`
	Total          int            `json:"total"`
	BillingAddress BillingAddress `json:"billing_address"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
}

// IPAddress VirtualMachine and Template represent the relevant fields of a VPS instance
type IPAddress struct {
	ID      int     `json:"id"`
	Address string  `json:"address"`
	PTR     *string `json:"ptr"`
}

type Template struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Documentation string `json:"documentation"`
}

type VirtualMachine struct {
	ID              int         `json:"id"`
	FirewallGroupID *int        `json:"firewall_group_id"`
	SubscriptionID  string      `json:"subscription_id"`
	DataCenterID    int         `json:"data_center_id"`
	Plan            string      `json:"plan"`
	Hostname        string      `json:"hostname"`
	State           string      `json:"state"`
	ActionsLock     string      `json:"actions_lock"`
	CPUs            int         `json:"cpus"`
	Memory          int         `json:"memory"`
	Disk            int         `json:"disk"`
	Bandwidth       int         `json:"bandwidth"`
	NS1             string      `json:"ns1"`
	NS2             string      `json:"ns2"`
	IPv4            []IPAddress `json:"ipv4"`
	IPv6            []IPAddress `json:"ipv6"`
	Template        *Template   `json:"template,omitempty"`
	CreatedAt       string      `json:"created_at"`
}

type PurchaseVMResponse struct {
	Order          Order          `json:"order"`
	VirtualMachine VirtualMachine `json:"virtual_machine"`
}

// PurchaseVirtualMachine Purchase Virtual Machine
func (c *HostingerClient) PurchaseVirtualMachine(purchaseRequest PurchaseVMRequest) (string, error) {
	url := c.BaseURL + "/api/vps/v1/virtual-machines"

	// Prepare request body
	reqBody := purchaseRequest
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyData))
	if err != nil {
		return "", err
	}
	c.addStandardHeaders(req)

	// Execute request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read error response for details
		errMsg, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to purchase virtual machine (HTTP %d, Payment Method %d): %s", resp.StatusCode, purchaseRequest.PaymentMethodID, string(errMsg))
	}

	// Parse successful order response
	var purchaseResp PurchaseVMResponse
	if err := json.NewDecoder(resp.Body).Decode(&purchaseResp); err != nil {
		return "", fmt.Errorf("invalid order response: %w", err)
	}
	return purchaseResp.Order.SubscriptionID, nil
}

// GetVirtualMachines lists all VPS instances in the account.
func (c *HostingerClient) GetVirtualMachines() ([]VirtualMachine, error) {
	url := c.BaseURL + "/api/vps/v1/virtual-machines"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list VPS instances (HTTP %d)", resp.StatusCode)
	}

	var vms []VirtualMachine
	if err := json.NewDecoder(resp.Body).Decode(&vms); err != nil {
		return nil, fmt.Errorf("could not decode VPS list: %w", err)
	}
	return vms, nil
}

// FindVirtualMachineBySubscription finds a VPS ID by its subscription ID.
func (c *HostingerClient) FindVirtualMachineBySubscription(subscriptionID string) (int, error) {
	vms, err := c.GetVirtualMachines()
	if err != nil {
		return 0, err
	}
	for _, vm := range vms {
		if vm.SubscriptionID == subscriptionID {
			return vm.ID, nil
		}
	}
	return 0, ErrNotFound
}

// SetupVirtualMachine activates a newly purchased VPS (with 'initial' state) by installing the OS.
func (c *HostingerClient) SetupVirtualMachine(vmID int, setup SetupRequest) (*VirtualMachine, error) {
	url := fmt.Sprintf("%s/api/vps/v1/virtual-machines/%d/setup", c.BaseURL, vmID)
	fmt.Printf("[DEBUG] Setup request body: %+v\n", setup)
	body := map[string]interface{}{
		"data_center_id": setup.DataCenterID,
		"template_id":    setup.TemplateID,
	}

	if setup.Hostname != nil && *setup.Hostname != "" {
		body["hostname"] = *setup.Hostname
	}

	if setup.Password != nil && *setup.Password != "" {
		body["password"] = *setup.Password
	}

	bodyData, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyData))
	if err != nil {
		return nil, err
	}
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to setup VPS (HTTP %d): %s", resp.StatusCode, string(errMsg))
	}

	var vm VirtualMachine
	if err := json.NewDecoder(resp.Body).Decode(&vm); err != nil {
		return nil, fmt.Errorf("invalid setup response: %w", err)
	}
	return &vm, nil
}

// GetVirtualMachine retrieves details for a specific VPS by ID.
func (c *HostingerClient) GetVirtualMachine(vmID int) (*VirtualMachine, error) {
	url := fmt.Sprintf("%s/api/vps/v1/virtual-machines/%d", c.BaseURL, vmID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get VPS (HTTP %d)", resp.StatusCode)
	}

	var vm VirtualMachine
	if err := json.NewDecoder(resp.Body).Decode(&vm); err != nil {
		return nil, fmt.Errorf("invalid VPS detail response: %w", err)
	}
	return &vm, nil
}

func (c *HostingerClient) UpdateHostname(vmID int, hostname string) error {
	url := fmt.Sprintf("%s/api/vps/v1/virtual-machines/%d/hostname", c.BaseURL, vmID)

	body := map[string]string{
		"hostname": hostname,
	}
	bodyData, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(bodyData))
	if err != nil {
		return err
	}

	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update hostname failed (HTTP %d): %s", resp.StatusCode, string(msg))
	}

	return nil
}

func (c *HostingerClient) RecreateVirtualMachine(vmID int, templateID int, password *string, postScriptID *int) error {
	url := fmt.Sprintf("%s/api/vps/v1/virtual-machines/%d/recreate", c.BaseURL, vmID)

	body := map[string]interface{}{
		"template_id": templateID,
	}
	if password != nil {
		body["password"] = *password
	}
	if postScriptID != nil {
		body["post_install_script_id"] = *postScriptID
	}

	bodyData, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyData))
	if err != nil {
		return err
	}
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("recreate VPS failed (HTTP %d): %s", resp.StatusCode, msg)
	}

	return nil
}

func (c *HostingerClient) GetSSHKeyIDsForVM(vmID int) ([]int, error) {
	url := fmt.Sprintf("%s/api/vps/v1/virtual-machines/%d/public-keys", c.BaseURL, vmID)

	req, _ := http.NewRequest("GET", url, nil)
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch SSH keys for VM (HTTP %d): %s", resp.StatusCode, msg)
	}

	var result struct {
		Data []struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	ids := make([]int, 0, len(result.Data))
	for _, k := range result.Data {
		ids = append(ids, k.ID)
	}
	return ids, nil
}
