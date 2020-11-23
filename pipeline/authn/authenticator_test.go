package authn_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/x"
)

const (
	key = "key"
	val = "value"
)

func TestSetHeader(t *testing.T) {
	assert := assert.New(t)
	for k, tc := range []struct {
		a    *authn.AuthenticationSession
		desc string
	}{
		{
			a:    &authn.AuthenticationSession{},
			desc: "should initiate Header field if it is nil",
		},
		{
			a:    &authn.AuthenticationSession{Header: map[string][]string{}},
			desc: "should add a header to AuthenticationSession",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.desc), func(t *testing.T) {
			tc.a.SetHeader(key, val)

			assert.NotNil(tc.a.Header)
			assert.Len(tc.a.Header, 1)
			assert.Equal(tc.a.Header.Get(key), val)
		})
	}
}

func TestCopy(t *testing.T) {
	assert := assert.New(t)
	original := &authn.AuthenticationSession{
		Subject: "ab",
		Extra:   map[string]interface{}{"a": "b", "b": map[string]string{"a:": "b"}},
		Header:  http.Header{"foo": {"bar", "baz"}},
		MatchContext: authn.MatchContext{
			RegexpCaptureGroups: []string{"a", "b"},
			URL:                 x.ParseURLOrPanic("https://foo/bar"),
		},
	}

	copied := original.Copy()
	copied.Subject = "ba"
	copied.Extra["baz"] = "bar"
	copied.Header.Add("bazbar", "bar")
	copied.MatchContext.URL.Host = "asdf"
	copied.MatchContext.RegexpCaptureGroups[0] = "b"

	assert.NotEqual(original.Subject, copied.Subject)
	assert.NotEqual(original.Extra, copied.Extra)
	assert.NotEqual(original.Header, copied.Header)
	assert.NotEqual(original.MatchContext.URL.Host, copied.MatchContext.URL.Host)
	assert.NotEqual(original.MatchContext.RegexpCaptureGroups, copied.MatchContext.RegexpCaptureGroups)
}

func TestUnmarshalIntoAuthenticationSession(t *testing.T) {
	// From example: https://www.ory.sh/oathkeeper/docs/pipeline/mutator#hydrator
	hydratorUpstreamPayload := bytes.NewBufferString(`{
		"subject": "anonymous",
		"extra": {
			"foo": "bar"
		},
		"header": {
			"foo": ["bar1", "bar2"]
		},
		"match_context": {
			"regexp_capture_groups": ["http", "foo"],
			"url": "http://domain.com/foo"
		}
	}`)
	sessionFromUpstream := authn.AuthenticationSession{}
	err := json.NewDecoder(hydratorUpstreamPayload).Decode(&sessionFromUpstream)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, sessionFromUpstream.Subject, "anonymous")
	assert.Equal(t, sessionFromUpstream.Extra["foo"], "bar")
	assert.Equal(t, sessionFromUpstream.MatchContext.RegexpCaptureGroups[0], "http")
	assert.Equal(t, sessionFromUpstream.MatchContext.URL.Host, "domain.com")
	assert.Equal(t, sessionFromUpstream.MatchContext.URL.Scheme, "http")
	assert.Equal(t, sessionFromUpstream.MatchContext.URL.Path, "/foo")
}
