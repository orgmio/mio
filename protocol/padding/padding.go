// Package padding 提供填充用的安全随机数。
package padding

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

type Range struct {
	Minimum int
	Maximum int
}

func RandomInt(minimum, maximum int) (int, error) {
	if minimum < 0 || maximum < minimum {
		return 0, errors.New("invalid random range")
	}
	span := big.NewInt(int64(maximum - minimum + 1))
	value, err := rand.Int(rand.Reader, span)
	if err != nil {
		return 0, err
	}
	return minimum + int(value.Int64()), nil
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
