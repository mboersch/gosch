// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package util

import (
	"fmt"
	"io"
	"log"
	"os"
)

type LogLevel int

const (
	INFO  LogLevel = 0
	DEBUG LogLevel = 1
	TRACE LogLevel = 2
	NOISE LogLevel = 3
)

type Logger interface {
	AddSink(io.Writer)
	SetLogLevel(LogLevel)
	Info(string, ...interface{})
	Error(string, ...interface{})
	Warn(string, ...interface{})
	Debug(string, ...interface{})
	Trace(string, ...interface{})
	Trace2(string, ...interface{})
}

func NewLogger(name string) Logger {
	rv := &simpleLogger{
		level: INFO,
	}
	rv.logger = log.New(rv, fmt.Sprintf("%s ", name), log.LstdFlags)
	rv.sinks = make(map[io.Writer]io.Writer)
	rv.AddSink(os.Stdout)
	return rv
}

type simpleLogger struct {
	name   string
	level  LogLevel
	logger *log.Logger
	sinks  map[io.Writer]io.Writer //XXX sequence delete is cumbersome
}

func (self *simpleLogger) AddSink(snk io.Writer) {
	self.sinks[snk] = snk
}
func (self *simpleLogger) RemoveSink(snk io.Writer) {
	delete(self.sinks, snk)
}
func (self *simpleLogger) SetLogLevel(lvl LogLevel) {
	if lvl >= INFO && lvl <= NOISE {
		self.level = lvl
	} else {
		self.level = NOISE
	}
}
func (self *simpleLogger) Info(msg string, args ...interface{}) {
	self.logger.Printf("%s", fmt.Sprintf(msg, args...))
}
func (self *simpleLogger) Error(msg string, args ...interface{}) {
	self.logger.Printf("[ERROR] %s", fmt.Sprintf(msg, args...))
}
func (self *simpleLogger) Warn(msg string, args ...interface{}) {
	self.logger.Printf("[WARN] %s", fmt.Sprintf(msg, args...))
}
func (self *simpleLogger) Debug(msg string, args ...interface{}) {
	if self.level >= DEBUG {
		self.Info(fmt.Sprintf("[DEBUG] %s", fmt.Sprintf(msg, args...)))
	}
}
func (self *simpleLogger) Trace(msg string, args ...interface{}) {
	if self.level >= TRACE {
		self.Info(fmt.Sprintf("[TRACE] %s", fmt.Sprintf(msg, args...)))
	}
}
func (self *simpleLogger) Trace2(msg string, args ...interface{}) {
	if self.level >= NOISE {
		self.Info(fmt.Sprintf("[TRACE] %s", fmt.Sprintf(msg, args...)))
	}
}

//io.Writer impl
func (self *simpleLogger) Write(p []byte) (n int, err error) {
	n = 0
	err = nil
	for _, out := range self.sinks {
		n, err = out.Write(p)
		if err != nil {
			return n, err
		}
	}
	return n, err
}
