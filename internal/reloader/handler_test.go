package reloader

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicHandler(t *testing.T) {
	// for ptr identity
	type testHandler struct{ http.Handler }

	hrFn := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	}

	hrFunc1 := &testHandler{hrFn()}
	hrFunc2 := &testHandler{hrFn()}
	assert.NotEqual(t, hrFunc1, hrFunc2)

	// a new AtomicHandler should be non-nil
	hr := NewAtomicHandler(nil)
	assert.NotNil(t, hr)

	// should have no stored handler
	{
		hrCur := hr.load()
		assert.Nil(t, hrCur)
		assert.Equal(t, true, hrCur == nil)
	}

	// should be non-nil after store
	for i := 0; i < 3; i++ {
		hr.Store(hrFunc1)
		assert.NotNil(t, hr.load())
		assert.Equal(t, hr.load(), hrFunc1)
		assert.Equal(t, hr.load() == hrFunc1, true)

		// should update to hrFunc2
		hr.Store(hrFunc2)
		assert.NotNil(t, hr.load())
		assert.Equal(t, hr.load(), hrFunc2)
		assert.Equal(t, hr.load() == hrFunc2, true)
	}
}
