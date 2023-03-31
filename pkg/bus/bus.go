package bus

import "github.com/montag451/go-eventbus"

const (
	CertChangeType_Cert         = "cert"
	CertChangeType_OCSPStapling = "ocspStapling"
)

type CertChangeEvent struct {
	CertName   string
	ChangeType string
}

func (e CertChangeEvent) Name() eventbus.EventName {
	return getCertChangeEventName(e.CertName)
}

func getCertChangeEventName(certName string) eventbus.EventName {
	return eventbus.EventName("certChange:" + certName)
}

type EventBus interface {
	PublishCertChange(certName, changeType string) error
	SubscribeCertChangeEvent(certName string, handler eventbus.HandlerFunc, opts ...eventbus.SubscribeOption) (*eventbus.Handler, error)
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

func (p *busImpl) PublishCertChange(certName, changeType string) error {
	return p.bus.PublishAsync(CertChangeEvent{
		CertName:   certName,
		ChangeType: changeType,
	})
}

func (p *busImpl) SubscribeCertChangeEvent(certName string, handler eventbus.HandlerFunc, opts ...eventbus.SubscribeOption) (*eventbus.Handler, error) {
	evtName := eventbus.EventNamePattern(getCertChangeEventName(certName))
	return p.bus.Subscribe(evtName, handler, opts...)
}

func (p *busImpl) Unsubscribe(h *eventbus.Handler) {
	_ = p.bus.Unsubscribe(h)
}

func (p *busImpl) Close() {
	p.bus.Close()
}
