package main

import (
	"testing"

	"nx-penne/internal/penne"
)

// An answer the console is blocking on goes out before anything queued, and
// is dropped rather than sent late: a late Ack is compared against the next
// request's string and aborts npns.
func TestAckTakesThePriorityPathAndIsNeverQueued(t *testing.T) {
	sess := &penneSession{prio: make(chan []byte, 1), send: make(chan penneOutbound, 4)}
	sess.ack("topic.subscription")
	sess.ack("aaaaaaaaaaaa0001/cccccccccccc0001") // would be late: dropped
	if len(sess.prio) != 1 {
		t.Fatalf("priority queue holds %d answers, want exactly the first", len(sess.prio))
	}
	if len(sess.send) != 0 {
		t.Fatalf("an answer was queued behind the notifications: %d", len(sess.send))
	}
	env, err := penne.DecodeEnvelope(<-sess.prio)
	if err != nil || env.Type() != penne.TypeAck {
		t.Fatalf("not an Ack: %v %v", env.TypeName(), err)
	}
	payload, _ := env.Payload()
	if got, _ := payload.String(0); got != "topic.subscription" {
		t.Fatalf("ack names %q", got)
	}
	sess.ack("") // nothing to answer
	if len(sess.prio) != 0 {
		t.Fatal("an empty name was answered")
	}
}
