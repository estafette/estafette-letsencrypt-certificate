package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateHostname(t *testing.T) {
	t.Run("ReturnsTrueIfHostnameHasAtLeast2LabelsAndOnlyAlphaNumericAndHyphenCharacters", func(t *testing.T) {

		// act
		valid := validateHostname("estafette.io")

		assert.True(t, valid)
	})

	t.Run("ReturnsTrueIfHostnameIsUppercase", func(t *testing.T) {

		// act
		valid := validateHostname("ESTAFETTE.IO")

		assert.True(t, valid)
	})

	t.Run("ReturnsTrueIfHostnameStartsWithWildcard", func(t *testing.T) {

		// act
		valid := validateHostname("*.estafette.io")

		assert.True(t, valid)
	})

	t.Run("ReturnsFalseIfHostnameHasWildcardAfterFirstCharacter", func(t *testing.T) {

		// act
		valid := validateHostname("*.estafette.io")

		assert.True(t, valid)
	})

	t.Run("ReturnsFalseIfHostHasLabelsLongerThan63Characters", func(t *testing.T) {

		// act
		valid := validateHostname("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl.estafette.io")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfHostIsLongerThan253Characters", func(t *testing.T) {

		// act
		valid := validateHostname("ab.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.estafette.io")

		assert.False(t, valid)
	})

	t.Run("ReturnsFalseIfHostHasOtherCharacterThanAlphaNumericOrHyphen", func(t *testing.T) {

		// act
		valid := validateHostname("gke_site.estafette.io")

		assert.False(t, valid)
	})
}
