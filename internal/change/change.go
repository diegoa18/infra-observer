package change

import (
	"sort"

	"infra-observer/internal/domain"
)

type PortChange struct {
	Port     int
	Protocol string
	Before   string
	After    string
}

type ServiceChangeKind string

const (
	ServiceAdded    ServiceChangeKind = "added"
	ServiceRemoved  ServiceChangeKind = "removed"
	ServiceModified ServiceChangeKind = "modified"
)

type ServiceChange struct {
	Kind        ServiceChangeKind
	Port        int
	Protocol    string
	BeforeName  string
	AfterName   string
	BeforeState string
	AfterState  string
}

type Result struct {
	Previous domain.Observation
	Current  domain.Observation
	Ports    []PortChange
	Services []ServiceChange
}

type endpoint struct {
	Port     int
	Protocol string
}

func Compare(
	previous domain.Observation,
	current domain.Observation,
) Result {
	result := Result{
		Previous: previous,
		Current:  current,
	}

	previousPorts := make(
		map[endpoint]domain.PortObservation,
		len(previous.Ports),
	)

	currentPorts := make(
		map[endpoint]domain.PortObservation,
		len(current.Ports),
	)

	for _, port := range previous.Ports {
		key := endpoint{
			Port:     port.Port,
			Protocol: port.Protocol,
		}

		previousPorts[key] = port
	}

	for _, port := range current.Ports {
		key := endpoint{
			Port:     port.Port,
			Protocol: port.Protocol,
		}

		currentPorts[key] = port
	}

	comparable := make(map[endpoint]struct{})

	for key, before := range previousPorts {
		after, exists := currentPorts[key]
		if !exists {
			continue
		}

		comparable[key] = struct{}{}

		if before.State == after.State {
			continue
		}

		result.Ports = append(
			result.Ports,
			PortChange{
				Port:     key.Port,
				Protocol: key.Protocol,
				Before:   before.State,
				After:    after.State,
			},
		)
	}

	previousServices := make(
		map[endpoint]domain.Service,
		len(previous.Services),
	)

	currentServices := make(
		map[endpoint]domain.Service,
		len(current.Services),
	)

	for _, service := range previous.Services {
		key := endpoint{
			Port:     service.Port,
			Protocol: service.Protocol,
		}

		previousServices[key] = service
	}

	for _, service := range current.Services {
		key := endpoint{
			Port:     service.Port,
			Protocol: service.Protocol,
		}

		currentServices[key] = service
	}

	for key := range comparable {
		before, existedBefore := previousServices[key]
		after, existsNow := currentServices[key]

		switch {
		case !existedBefore && existsNow:
			result.Services = append(
				result.Services,
				ServiceChange{
					Kind:       ServiceAdded,
					Port:       key.Port,
					Protocol:   key.Protocol,
					AfterName:  after.Name,
					AfterState: string(after.State),
				},
			)

		case existedBefore && !existsNow:
			result.Services = append(
				result.Services,
				ServiceChange{
					Kind:        ServiceRemoved,
					Port:        key.Port,
					Protocol:    key.Protocol,
					BeforeName:  before.Name,
					BeforeState: string(before.State),
				},
			)

		case existedBefore && existsNow:
			if before.Name == after.Name &&
				before.State == after.State {
				continue
			}

			result.Services = append(
				result.Services,
				ServiceChange{
					Kind:        ServiceModified,
					Port:        key.Port,
					Protocol:    key.Protocol,
					BeforeName:  before.Name,
					AfterName:   after.Name,
					BeforeState: string(before.State),
					AfterState:  string(after.State),
				},
			)
		}
	}

	sort.Slice(result.Ports, func(i, j int) bool {
		if result.Ports[i].Port == result.Ports[j].Port {
			return result.Ports[i].Protocol <
				result.Ports[j].Protocol
		}

		return result.Ports[i].Port <
			result.Ports[j].Port
	})

	sort.Slice(result.Services, func(i, j int) bool {
		if result.Services[i].Port == result.Services[j].Port {
			if result.Services[i].Protocol ==
				result.Services[j].Protocol {
				return result.Services[i].Kind <
					result.Services[j].Kind
			}

			return result.Services[i].Protocol <
				result.Services[j].Protocol
		}

		return result.Services[i].Port <
			result.Services[j].Port
	})

	return result
}

func (r Result) Empty() bool {
	return len(r.Ports) == 0 &&
		len(r.Services) == 0
}
