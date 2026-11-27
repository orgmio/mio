// Package padding 提供填充用的安全随机数。
package padding

import (
	"crypto/rand"
	"errors"
	"io"
	randv2 "math/rand/v2"
)

type Range struct {
	Minimum int
	Maximum int
}

func RandomInt(minimum, maximum int) (int, error) {
	if minimum < 0 || maximum < minimum {
		return 0, errors.New("invalid random range")
	}
	return minimum + randv2.IntN(maximum-minimum+1), nil
}

func RandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("negative padding length")
	}
	padding := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, err
	}
	return padding, nil
}
