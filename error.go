package fastauth

import (
	"reflect"
	"runtime"
	"strconv"
)

type ErrInvalidInput string

func NewInvalidInputErr(f interface{}) ErrInvalidInput {
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	return ErrInvalidInput(fn)
}

func (e ErrInvalidInput) Error() string {
	return strconv.Quote(string(e)) + " function has received an invalid input"
}
