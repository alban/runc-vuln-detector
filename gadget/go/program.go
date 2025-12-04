package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	if api.KallsymsSymbolExists("user_path_at") {
		api.SetConfig("programs.user_path_at_e.attach_to", "user_path_at")
		api.SetConfig("programs.ig_user_path_at_x.attach_to", "user_path_at")
	}
	return 0
}

func main() {}
