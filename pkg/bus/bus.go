package bus

import "github.com/montag451/go-eventbus"

const (
	ChangeType_Cert         = "cert"
	ChangeType_OCSPStapling = "ocspStapling"
)

type CertChangeEvent struct {
	CertKey    string
	ChangeType string
}

func (e CertChangeEvent) Name() eventbus.EventName {
	return getCertChangeEventName(e.CertKey)
}

func getCertChangeEventName(certName string) eventbus.EventName {
	return eventbus.EventName("certChange/" + certName)
}

type EventBus interface {
	PublishCertChange(certKey, changeType string) error
	SubscribeCertChanges(certKey string, handler eventbus.HandlerFunc, opts ...eventbus.SubscribeOption) (*eventbus.Handler, error)
	Unsubscribe(handler *eventbus.Handler)
	Close()
}

func NewEventBus() EventBus {
	closeCh := make(chan struct{})
	bus := eventbus.New(eventbus.WithClosedHandler(func() {
		close(closeCh)
	}))
	return &busImpl{
		bus:     bus,
		closeCh: closeCh,
	}
}

type busImpl struct {
	bus     *eventbus.Bus
	closeCh chan struct{}
}

func (p *busImpl) PublishCertChange(certKey, changeType string) error {
	return p.bus.PublishAsync(CertChangeEvent{
		CertKey:    certKey,
		ChangeType: changeType,
	})
}

func (p *busImpl) SubscribeCertChanges(certKey string, handler eventbus.HandlerFunc, opts ...eventbus.SubscribeOption) (*eventbus.Handler, error) {
	evtName := eventbus.EventNamePattern(getCertChangeEventName(certKey))
	return p.bus.Subscribe(evtName, handler, opts...)
}

func (p *busImpl) Unsubscribe(h *eventbus.Handler) {
	_ = p.bus.Unsubscribe(h)
}

func (p *busImpl) Close() {
	p.bus.Close()
}
