//go:build !volframandroid

package main

func (e *Engine) extUp(sv *Server, s Settings) (chan struct{}, error) { return nil, nil }
func (e *Engine) extDown(stopVPN bool)                                {}
func platformPreConnect()                                             {}
func platformAbort()                                                  {}
func sysDNS() []string                                                { return nil }
