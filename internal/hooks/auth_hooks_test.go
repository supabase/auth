package hooks

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type HookTestSuite struct {
	suite.Suite
}

func TestHooks(t *testing.T) {
	ts := &HookTestSuite{}
	suite.Run(t, ts)
}
func (ts *HookTestSuite) SetupTest() {
	// TODO

}

func (ts *HookTestSuite) TestFetchHookName() {
	// TODO
}
