package list

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cli/cli/v2/internal/ghrepo"
	"github.com/cli/cli/v2/pkg/cmd/repo/autolink/shared"
	"github.com/cli/cli/v2/pkg/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutolinkLister_List(t *testing.T) {
	tests := []struct {
		name   string
		repo   ghrepo.Interface
		resp   []shared.Autolink
		status int
	}{
		{
			name:   "no autolinks",
			repo:   ghrepo.New("OWNER", "REPO"),
			resp:   []shared.Autolink{},
			status: http.StatusOK,
		},
		{
			name: "two autolinks",
			repo: ghrepo.New("OWNER", "REPO"),
			resp: []shared.Autolink{
				{
					ID:             1,
					IsAlphanumeric: true,
					KeyPrefix:      "key",
					URLTemplate:    "https://example.com",
				},
				{
					ID:             2,
					IsAlphanumeric: false,
					KeyPrefix:      "key2",
					URLTemplate:    "https://example2.com",
				},
			},
			status: http.StatusOK,
		},
		{
			name:   "http error",
			repo:   ghrepo.New("OWNER", "REPO"),
			status: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := &httpmock.Registry{}
			reg.Register(
				httpmock.REST(http.MethodGet, fmt.Sprintf("repos/%s/%s/autolinks", tt.repo.RepoOwner(), tt.repo.RepoName())),
				httpmock.StatusJSONResponse(tt.status, tt.resp),
			)
			defer reg.Verify(t)

			autolinkLister := &AutolinkLister{
				HTTPClient: &http.Client{Transport: reg},
			}
			autolinks, err := autolinkLister.List(tt.repo)
			if tt.status == http.StatusNotFound {
				require.Error(t, err)
				assert.Equal(t, "error getting autolinks: HTTP 404: Perhaps you are missing admin rights to the repository? (https://api.github.com/repos/OWNER/REPO/autolinks)", err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.resp, autolinks)
			}
		})
	}
}
