package firewall

// NoopManager implements Manager with no-op operations.
type NoopManager struct{}

// NewNoopManager returns a firewall Manager that does nothing.
func NewNoopManager() *NoopManager {
	return &NoopManager{}
}

func (n *NoopManager) OpenPort(proto Protocol, port uint16) error {
	return nil
}

func (n *NoopManager) ClosePort(proto Protocol, port uint16) error {
	return nil
}

func (n *NoopManager) Close() error {
	return nil
}
