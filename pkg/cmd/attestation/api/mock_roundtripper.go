package api

import (
	"fmt"
	"net/http"
)

type MockRoundTripper struct{}

func (t MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("round trip failed")
}
