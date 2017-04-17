package main

import (
	"encoding/json"
	"errors"
	"log"
)

type ErrCode int

const (
	ERR_NONE                ErrCode = 1 + iota
	ERR_KEY_UNKNOWN                 = iota
	ERR_ENCRYPTION                  = iota
	ERR_TASK_INVALID                = iota
	ERR_NOT_ALLOWED                 = iota
	ERR_OTHER_UNRECOVERABLE         = iota
	ERR_OTHER_RECOVERABLE           = iota
)

type MyError struct {
	Error error
	Code  ErrCode
}

func (me MyError) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		struct {
			Error string
			Code  ErrCode
		}{
			Error: me.Error.Error(),
			Code:  me.Code,
		})
}

func (me *MyError) UnmarshalJSON(data []byte) error {
	var s struct {
		Error string
		Code  ErrCode
	}
	err := json.Unmarshal(data, &s)
	me.Error = errors.New(s.Error)
	me.Code = s.Code
	return err
}

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}
