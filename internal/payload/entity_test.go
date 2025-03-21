package payload

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterfaceGetGfXSS(t *testing.T) {
	list, length := InterfaceGetGfXSS()
	assert.NotNil(t, list)
	assert.Greater(t, length, 0)
}

func TestInterfaceGetEventHandlers(t *testing.T) {
	list, length := InterfaceGetEventHandlers()
	assert.NotNil(t, list)
	assert.Greater(t, length, 0)
}

func TestInterfaceGetTags(t *testing.T) {
	list, length := InterfaceGetTags()
	assert.NotNil(t, list)
	assert.Greater(t, length, 0)
}

func TestInterfaceGetSpecialChar(t *testing.T) {
	list, length := InterfaceGetSpecialChar()
	assert.NotNil(t, list)
	assert.Greater(t, length, 0)
}

func TestInterfaceGetUsefulCode(t *testing.T) {
	list, length := InterfaceGetUsefulCode()
	assert.NotNil(t, list)
	assert.Greater(t, length, 0)
}
