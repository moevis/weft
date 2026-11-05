package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"weft/internal/hub"
)

func list(ctx context.Context, address, channel string, machine bool) error {
	services, err := hub.List(ctx, address, channel)
	if err != nil {
		return err
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	if machine {
		if services == nil {
			services = []hub.Service{}
		}
		return json.NewEncoder(os.Stdout).Encode(services)
	}
	if len(services) == 0 {
		fmt.Fprintln(os.Stdout, "No services published.")
		return nil
	}
	for _, service := range services {
		state := "offline"
		if service.Online {
			state = "online"
		}
		fmt.Fprintf(os.Stdout, "%s\t%s\n", service.Name, state)
	}
	return nil
}
