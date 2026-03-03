package apierrors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	err := initMetrics(errorCodesMap)
	require.NoError(t, err)
}
