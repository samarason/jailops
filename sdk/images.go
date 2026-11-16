package sdk

import (
	"context"
	"iter"
	"net/http"
	"strconv"

	"jailops.net/jailops/sdk/api"
)

// ImageClient accesses /api/v1/images.
type ImageClient struct {
	*Resource[api.Image]
}

// Images returns the images client.
func (c *Client) Images() *ImageClient {
	return &ImageClient{newResource[api.Image](c, "/api/v1/images")}
}

// Generations iterates the generations of an image.
func (i *ImageClient) Generations(ctx context.Context, image string) iter.Seq2[api.ImageGeneration, error] {
	if err := i.c.need("image_generations"); err != nil {
		return func(y func(api.ImageGeneration, error) bool) { y(api.ImageGeneration{}, err) }
	}
	return list[api.ImageGeneration](ctx, i.c, i.item(image)+"/generations", nil)
}

// Build builds the next generation of an image; the result is that generation.
func (i *ImageClient) Build(ctx context.Context, image string, b api.ImageBuild) (*Operation[api.ImageGeneration], error) {
	if err := i.c.need("image_generations"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[api.ImageGeneration](ctx, i.c, request{method: http.MethodPost, path: i.item(image) + "/generations", body: b}, nil)
	return op, err
}

// Upgrade builds the next generation of an image from its newest one and
// moves the thin jails that use the image to it, one at a time, stopping at
// the first jail that fails. The result says what happened to each jail.
func (i *ImageClient) Upgrade(ctx context.Context, image string, u api.ImageUpgrade) (*Operation[api.ImageUpgradeResult], error) {
	if err := i.c.need("image_upgrade"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[api.ImageUpgradeResult](ctx, i.c, request{method: http.MethodPost, path: i.item(image) + "/upgrade", body: u}, nil)
	return op, err
}

// DeleteGeneration deletes an unreferenced generation.
func (i *ImageClient) DeleteGeneration(ctx context.Context, image string, number int) (*Operation[None], error) {
	op, _, err := sendOp[None](ctx, i.c, request{method: http.MethodDelete, path: i.item(image) + "/generations/" + strconv.Itoa(number)}, nil)
	return op, err
}

// SetAlias points an alias of an image at a generation; zero means the newest. It returns the updated image.
func (i *ImageClient) SetAlias(ctx context.Context, image, alias string, generation int) (api.Image, error) {
	if err := i.c.need("image_aliases"); err != nil {
		return api.Image{}, err
	}
	out, _, err := send[api.Image](ctx, i.c, request{method: http.MethodPut, path: i.item(image) + "/aliases/" + esc(alias), body: api.ImageAliasSet{Generation: generation}})
	return out, err
}

// DeleteAlias removes an alias of an image. It returns the updated image.
func (i *ImageClient) DeleteAlias(ctx context.Context, image, alias string) (api.Image, error) {
	if err := i.c.need("image_aliases"); err != nil {
		return api.Image{}, err
	}
	out, _, err := send[api.Image](ctx, i.c, request{method: http.MethodDelete, path: i.item(image) + "/aliases/" + esc(alias)})
	return out, err
}

// NetworkClient accesses /api/v1/networks.
type NetworkClient struct {
	*Resource[api.Network]
}

// Networks returns the networks client.
func (c *Client) Networks() *NetworkClient {
	return &NetworkClient{newResource[api.Network](c, "/api/v1/networks")}
}

// Leases iterates the addresses allocated on a network.
func (n *NetworkClient) Leases(ctx context.Context, network string) iter.Seq2[api.Lease, error] {
	return list[api.Lease](ctx, n.c, n.item(network)+"/leases", nil)
}

// FirewallClient groups the firewall resources.
type FirewallClient struct{ c *Client }

// Firewall returns the firewall client.
func (c *Client) Firewall() *FirewallClient { return &FirewallClient{c} }

// Policies accesses /api/v1/firewall/policies.
func (f *FirewallClient) Policies() *Resource[api.FirewallPolicy] {
	return newResource[api.FirewallPolicy](f.c, "/api/v1/firewall/policies")
}

// AddressSets accesses /api/v1/firewall/address-sets.
func (f *FirewallClient) AddressSets() *Resource[api.AddressSet] {
	return newResource[api.AddressSet](f.c, "/api/v1/firewall/address-sets")
}

// Test asks whether a new connection would pass the firewall, and which rule decides at each anchor it meets
// (POST /api/v1/firewall/test).
func (f *FirewallClient) Test(ctx context.Context, req api.FirewallTestRequest) (api.FirewallTestResult, error) {
	if err := f.c.need("firewall_test"); err != nil {
		return api.FirewallTestResult{}, err
	}
	out, _, err := send[api.FirewallTestResult](ctx, f.c, request{method: http.MethodPost, path: "/api/v1/firewall/test", body: req})
	return out, err
}
