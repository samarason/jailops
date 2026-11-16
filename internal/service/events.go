package service

import (
	"context"
	"encoding/json"
	"jailops.net/jailops/internal/supervise"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/sdk/api"
)

// eventBus stores events in the store ring (so a reconnecting client can
// replay them) and fans them out to live subscribers.
type eventBus struct {
	db   *store.Store
	host string

	mu     sync.Mutex
	subs   map[*subscription]struct{}
	closed bool
	last   int64 // id of the newest event
}

type subscription struct {
	ch      chan store.StoredEvent
	dropped bool
}

const subscriberBuffer = 512

func newEventBus(db *store.Store, host string) *eventBus {
	b := &eventBus{db: db, host: host, subs: map[*subscription]struct{}{}}
	var after int64
	for {
		evs, err := db.Events.Since(context.Background(), after, 1000)
		if err != nil || len(evs) == 0 {
			break
		}
		after = evs[len(evs)-1].ID
	}
	b.last = after
	return b
}

func (b *eventBus) publish(t api.EventType, meta any, now time.Time) {
	raw, err := json.Marshal(meta)
	if err != nil {
		return
	}
	ev := api.Event{Type: t, Timestamp: now.UTC(), Host: b.host, Metadata: raw}
	// The append and the fan-out share the lock so subscribers see ids in order.
	b.mu.Lock()
	defer b.mu.Unlock()
	id, err := b.db.Events.Append(context.Background(), ev)
	if err != nil {
		return
	}
	se := store.StoredEvent{ID: id, Event: ev}
	b.last = id
	for sub := range b.subs {
		select {
		case sub.ch <- se:
		default:
			// A slow consumer is cut off; it reconnects with Last-Event-ID.
			sub.dropped = true
			close(sub.ch)
			delete(b.subs, sub)
		}
	}
}

func (b *eventBus) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for sub := range b.subs {
		close(sub.ch)
		delete(b.subs, sub)
	}
}

// EventBus is the server's view of the event bus.
type EventBus struct{ b *eventBus }

// Last is the id of the newest event (0 before the first one).
func (e *EventBus) Last() int64 {
	e.b.mu.Lock()
	defer e.b.mu.Unlock()
	return e.b.last
}

// Subscribe returns a channel of events with id greater than after (a negative
// value means "from now"): first the retained ones, then live ones, without
// gaps or duplicates. The channel is
// closed when ctx ends, the bus closes or the subscriber falls too far behind.
func (e *EventBus) Subscribe(ctx context.Context, after int64) <-chan store.StoredEvent {
	out := make(chan store.StoredEvent, 64)
	sub := &subscription{ch: make(chan store.StoredEvent, subscriberBuffer)}
	b := e.b
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		close(out)
		return out
	}
	b.subs[sub] = struct{}{}
	if after < 0 {
		after = b.last
	}
	b.mu.Unlock()
	go func() {
		defer func() { supervise.Report(nil, "event-stream", recover()) }()
		defer close(out)
		defer func() {
			b.mu.Lock()
			if _, ok := b.subs[sub]; ok {
				delete(b.subs, sub)
				close(sub.ch)
			}
			b.mu.Unlock()
		}()
		last := after
		send := func(se store.StoredEvent) bool {
			if se.ID <= last {
				return true
			}
			select {
			case out <- se:
				last = se.ID
				return true
			case <-ctx.Done():
				return false
			}
		}
		// Replay in pages; live events queue in sub.ch meanwhile.
		for {
			evs, err := b.db.Events.Since(ctx, last, 500)
			if err != nil || len(evs) == 0 {
				break
			}
			for _, se := range evs {
				if !send(se) {
					return
				}
			}
		}
		for {
			select {
			case se, ok := <-sub.ch:
				if !ok {
					return
				}
				if !send(se) {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// emit publishes a lifecycle event of a host-level object (no project)
// caused by the actor in ctx.
func (s *Service) emit(ctx context.Context, action, source string) {
	s.emitIn(ctx, "", action, source)
}

// emitIn publishes a lifecycle event of an object of project.
func (s *Service) emitIn(ctx context.Context, project, action, source string) {
	for _, p := range []string{"/api/v1/tokens/", "/api/v1/users/", "/api/v1/certificates/", "/api/v1/sessions/"} {
		if strings.HasPrefix(source, p) {
			s.credGen.Add(1)
		}
	}
	s.events.publish(api.EventLifecycle, api.LifecycleEvent{Action: action, Source: source, Requestor: ActorFrom(ctx).Name, Project: project}, s.now())
}

func (s *Service) emitOperation(op api.Operation) {
	s.events.publish(api.EventOperation, op, s.now())
}

// CredentialGeneration changes whenever a token, user, certificate or session changes or goes away: a long stream
// that saw another value checks its credential again before it sends anything more.
func (s *Service) CredentialGeneration() int64 { return s.credGen.Load() }

// Log publishes a logging event (used for dry-run plans and warnings).
func (s *Service) logEvent(level, msg string, fields map[string]string) {
	s.events.publish(api.EventLogging, map[string]any{"level": level, "message": msg, "fields": fields}, s.now())
}

// EventFilter returns the visibility rule of a caller for the event stream:
// events of a project go to the identities that may use it, events of
// host-level objects (no project) and log events to global identities, and a
// project named in the request narrows everything to that project. A project
// the caller may not use is not_found.
func (s *Service) EventFilter(ctx context.Context) (func(api.Event) bool, error) {
	all, projects, err := s.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	return func(ev api.Event) bool {
		if ev.Type == api.EventLogging {
			return all
		}
		var m struct {
			Project string `json:"project"`
		}
		_ = json.Unmarshal(ev.Metadata, &m)
		if m.Project == "" {
			return all
		}
		return all || slices.Contains(projects, m.Project)
	}, nil
}
