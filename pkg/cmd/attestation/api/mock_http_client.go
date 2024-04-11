package api

import (
	"fmt"
	"net/http"
)

type FailHTTPClient struct{}

func (c *FailHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("failed to do request")
}

type FailWithCodeHTTPClient struct {
	StatusCode int
}

func (c *FailWithCodeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.StatusCode,
	}, nil
}
