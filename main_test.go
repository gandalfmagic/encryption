package encryption

import (
	"math/rand"
	"time"
)

func testRandomString(l int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	r := rand.New(rand.NewSource(time.Now().Unix()))
	s := make([]rune, l)
	for i := range s {
		s[i] = letters[r.Intn(len(letters))]
	}

	return string(s)
}
