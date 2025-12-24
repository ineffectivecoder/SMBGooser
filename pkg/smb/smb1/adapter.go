// Transport adapter for bridging SMB1 client with SMB2/3 transport
package smb1

// TransportAdapter wraps an SMB transport to implement the SMB1 Transport interface
type TransportAdapter struct {
	SendRecvFunc func(data []byte) ([]byte, error)
	CloseFunc    func() error
}

// SendRecv sends an SMB1 message and receives the response
func (a *TransportAdapter) SendRecv(data []byte) ([]byte, error) {
	return a.SendRecvFunc(data)
}

// Close closes the transport
func (a *TransportAdapter) Close() error {
	if a.CloseFunc != nil {
		return a.CloseFunc()
	}
	return nil
}
