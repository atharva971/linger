package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simplexai-labs/linger/apps/computer/local-daemon/internal/protocol"
)

// heartbeatFailingStream fails every send, standing in for a dead connection.
type heartbeatFailingStream struct {
	*fakeStream
	closes atomic.Int32
}

func (s *heartbeatFailingStream) Send(context.Context, protocol.Event) error {
	return errors.New("connection closed")
}

func (s *heartbeatFailingStream) Close() error {
	s.closes.Add(1)
	return nil
}

// A failed heartbeat closes the stream so Receive ends and the daemon reconnects.
func TestHeartbeatSendFailureClosesStream(t *testing.T) {
	d := &Daemon{}
	stream := &heartbeatFailingStream{fakeStream: &fakeStream{}}
	done := make(chan struct{})
	go func() {
		d.heartbeatLoop(context.Background(), stream, 1000)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeatLoop kept running after a failed send")
	}
	if got := stream.closes.Load(); got != 1 {
		t.Fatalf("stream closes=%d, want 1", got)
	}
}
