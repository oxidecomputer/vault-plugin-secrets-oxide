package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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
			logical.CreateOperation: b.pathPrincipalCreateUpdate,
			logical.UpdateOperation: b.pathPrincipalCreateUpdate,
			logical.DeleteOperation: b.pathPrincipalDelete,
			logical.ReadOperation:   b.pathPrincipalRead,
		},
		ExistenceCheck: b.pathPrincipalExistenceCheck,
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

func (b *backend) pathPrincipalCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

func (b *backend) pathPrincipalDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	principalName := d.Get("name").(string)
	if principalName == "" {
		return logical.ErrorResponse("must set principal name"), nil
	}

	if err := req.Storage.Delete(ctx, "principal/"+strings.ToLower(principalName)); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathPrincipalRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
		"default_ttl": principal.DefaultTTL,
		"max_ttl":     principal.MaxTTL,
	}
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathPrincipalExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	principal, err := b.getPrincipal(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return principal != nil, nil
}
