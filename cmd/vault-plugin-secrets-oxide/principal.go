package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type oxidePrincipal struct {
	Host       string        `json:"host"`
	Token      string        `json:"token"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
}

func (b *backend) pathPrincipal() *framework.Path {
	return &framework.Path{
		Pattern: "principal/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:     framework.TypeLowerCaseString,
				Required: true,
			},
			"host": {
				Type: framework.TypeString,
			},
			"token": {
				Type: framework.TypeString,
			},
			"default_ttl": {
				Type: framework.TypeDurationSecond,
			},
			"max_ttl": {
				Type: framework.TypeDurationSecond,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.handlePrincipalCreateUpdate,
			logical.UpdateOperation: b.handlePrincipalCreateUpdate,
			logical.DeleteOperation: b.handlePrincipalDelete,
			logical.ReadOperation:   b.handlePrincipalRead,
		},
		ExistenceCheck: b.handlePrincipalExistenceCheck,
	}
}

func (b *backend) pathListPrincipal() *framework.Path {
	return &framework.Path{
		Pattern: "principal/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handlePrincipal,
			},
		},
	}
}

func (b *backend) getPrincipal(ctx context.Context, s logical.Storage, name string) (*oxidePrincipal, error) {
	raw, err := s.Get(ctx, "principal/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	principal := new(oxidePrincipal)
	if err := json.Unmarshal(raw.Value, principal); err != nil {
		return nil, err
	}
	return principal, nil
}

func (b *backend) handlePrincipalCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	principalName := d.Get("name").(string)
	if principalName == "" {
		return logical.ErrorResponse("must set principal name"), nil
	}

	principal, err := b.getPrincipal(ctx, req.Storage, principalName)
	if err != nil {
		return nil, err
	}

	if principal == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("principal entry not found during update operation")
		}
		principal = new(oxidePrincipal)
	}

	if host, ok := d.GetOk("host"); ok {
		principal.Host = host.(string)
	}
	if token, ok := d.GetOk("token"); ok {
		principal.Token = token.(string)
	}
	if defaultTTL, ok := d.GetOk("default_ttl"); ok {
		principal.DefaultTTL = time.Second * time.Duration(defaultTTL.(int))
	}
	if maxTTL, ok := d.GetOk("max_ttl"); ok {
		principal.MaxTTL = time.Second * time.Duration(maxTTL.(int))
	}

	entry, err := logical.StorageEntryJSON("principal/"+strings.ToLower(principalName), principal)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for principal %s", principalName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) handlePrincipalDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	principalName := d.Get("name").(string)
	if principalName == "" {
		return logical.ErrorResponse("must set principal name"), nil
	}

	if err := req.Storage.Delete(ctx, "principal/"+strings.ToLower(principalName)); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) handlePrincipalRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	principalName := d.Get("name").(string)
	if principalName == "" {
		return logical.ErrorResponse("must set principal name"), nil
	}
	principal, err := b.getPrincipal(ctx, req.Storage, principalName)
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, nil
	}
	data := map[string]any{
		"host":        principal.Host,
		"default_ttl": principal.DefaultTTL.Seconds(),
		"max_ttl":     principal.MaxTTL.Seconds(),
	}
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) handlePrincipal(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	principals, err := req.Storage.List(ctx, "principal/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(principals), nil
}

func (b *backend) handlePrincipalExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	principal, err := b.getPrincipal(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return principal != nil, nil
}
