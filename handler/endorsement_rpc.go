// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package handler

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/rpc"

	"github.com/veraison/services/plugin"
)

/*
  Server-side RPC adapter around the Decoder plugin implementation
  (plugin-side)
*/

var EndorsementHandlerRPC = &plugin.RPCChannel[IEndorsementHandler]{
	GetClient: getEndorsementClient,
	GetServer: geEndorsementServer,
}

func getEndorsementClient(c *rpc.Client) interface{} {
	return &EndorsementRPCClient{client: c}
}

func geEndorsementServer(i IEndorsementHandler) interface{} {
	return &EndorsementRPCServer{Impl: i}
}

// DecodeArgs encapsulates the arguments for the Decode RPC call
type DecodeArgs struct {
	Data      []byte
	MediaType string
	CACerts   []string // PEM-encoded CA certificates
}

type EndorsementRPCServer struct {
	Impl IEndorsementHandler
}

func (s *EndorsementRPCServer) Init(params EndorsementHandlerParams, unused interface{}) error {
	return s.Impl.Init(params)
}

func (s EndorsementRPCServer) Close(unused0 interface{}, unused1 interface{}) error {
	return s.Impl.Close()
}

func (s *EndorsementRPCServer) GetName(args interface{}, resp *string) error {
	*resp = s.Impl.GetName()
	return nil
}

func (s *EndorsementRPCServer) GetAttestationScheme(args interface{}, resp *string) error {
	*resp = s.Impl.GetAttestationScheme()
	return nil
}

func (s *EndorsementRPCServer) GetSupportedMediaTypes(args interface{}, resp *[]string) error {
	*resp = s.Impl.GetSupportedMediaTypes()
	return nil
}

func (s EndorsementRPCServer) Decode(args *DecodeArgs, resp *[]byte) error {
	// Create a cert pool from the PEM-encoded certs
	var certPool *x509.CertPool
	if len(args.CACerts) > 0 {
		certPool = x509.NewCertPool()
		for _, pemCert := range args.CACerts {
			if !certPool.AppendCertsFromPEM([]byte(pemCert)) {
				return fmt.Errorf("failed to parse PEM certificate")
			}
		}
	}

	j, err := s.Impl.Decode(args.Data, args.MediaType, certPool)
	if err != nil {
		return fmt.Errorf("plugin %q returned error: %w", s.Impl.GetName(), err)
	}

	*resp, err = json.Marshal(j)
	if err != nil {
		return fmt.Errorf("failed to marshal plugin response: %w", err)
	}

	return nil
}

/*
  RPC client
  (plugin caller side)
*/

type EndorsementRPCClient struct {
	client *rpc.Client
}

func (c EndorsementRPCClient) Init(params EndorsementHandlerParams) error {
	var unused interface{}

	return c.client.Call("Plugin.Init", params, &unused)
}

func (c EndorsementRPCClient) Close() error {
	var unused0, unused1 interface{}

	return c.client.Call("Plugin.Close", unused0, &unused1)
}

func (c EndorsementRPCClient) GetName() string {
	var resp string

	err := c.client.Call("Plugin.GetName", nil, &resp)
	if err != nil {
		return fmt.Sprintf("error calling GetName: %v", err)
	}

	return resp
}

func (c EndorsementRPCClient) GetAttestationScheme() string {
	var resp string

	err := c.client.Call("Plugin.GetAttestationScheme", nil, &resp)
	if err != nil {
		return fmt.Sprintf("error calling GetAttestationScheme: %v", err)
	}

	return resp
}

func (c EndorsementRPCClient) GetSupportedMediaTypes() []string {
	var resp []string

	err := c.client.Call("Plugin.GetSupportedMediaTypes", nil, &resp)
	if err != nil {
		return []string{fmt.Sprintf("error calling GetSupportedMediaTypes: %v", err)}
	}

	return resp
}

func (c EndorsementRPCClient) Decode(data []byte, mediaType string, caCertPool *x509.CertPool) (*EndorsementHandlerResponse, error) {
	var resp []byte

	// CA certificates cannot currently be passed through RPC
	// This is a known limitation in the current implementation
	var caCerts []string
	// TODO: implement proper extraction of certificates from the pool
	// Currently, we can't extract certificates from the pool via public API

	args := &DecodeArgs{
		Data:      data,
		MediaType: mediaType,
		CACerts:   caCerts,
	}

	if err := c.client.Call("Plugin.Decode", args, &resp); err != nil {
		return nil, err
	}

	var r EndorsementHandlerResponse
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}

	return &r, nil
}
