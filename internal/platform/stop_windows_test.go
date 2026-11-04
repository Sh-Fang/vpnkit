package platform

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestStopContext(t *testing.T) {
	ctx, release, err := StopContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := requestStop(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("stop event did not cancel context")
	}
}

func TestStopContextRelease(t *testing.T) {
	ctx, release, err := StopContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if ctx.Err() == nil {
		t.Fatal("release must cancel context")
	}
	// 事件已关闭：down 应退回强制结束
	if err := requestStop(os.Getpid()); err == nil {
		t.Fatal("expected error after release")
	}
}
