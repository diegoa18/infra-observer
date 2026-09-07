package domain

type ServiceState string

const (
	ServiceAccessible ServiceState = "accessible"
)

type Service struct {
	Port     int
	Protocol string
	Name     string
	State    ServiceState
	Banner   string
	Metadata map[string]string
}
