package source

import (
	"fmt"
	"log"
	"runtime"

	"github.com/vishvananda/netns"
)

func newNetnsPacketSource(procfs string, pid string, interfaceName string, packetCapture string) (*TcpPacketSource, error) {
	nsh, err := netns.GetFromPath(fmt.Sprintf("%s/%s/ns/net", procfs, pid))

	if err != nil {
		log.Printf("Unable to get netns of pid %s - %v", pid, err)
		return nil, err
	}

	src, err := newPacketSourceFromNetnsHandle(pid, nsh, interfaceName, packetCapture)

	if err != nil {
		log.Printf("Error starting netns packet source for %s - %v", pid, err)
		return nil, err
	}

	return src, nil
}

func newPacketSourceFromNetnsHandle(pid string, nsh netns.NsHandle, interfaceName string, packetCapture string) (*TcpPacketSource, error) {

	done := make(chan *TcpPacketSource)
	errors := make(chan error)

	go func(done chan<- *TcpPacketSource) {
		// Setting a netns should be done from a dedicated OS thread.
		//
		// goroutines are not really OS threads, we try to mimic the issue by
		//	locking the OS thread to this goroutine
		//
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		oldnetns, err := netns.Get()

		if err != nil {
			log.Printf("Unable to get netns of current thread %v", err)
			errors <- err
			return
		}

		if err := netns.Set(nsh); err != nil {
			log.Printf("Unable to set netns of pid %s - %v", pid, err)
			errors <- err
			return
		}

		name := fmt.Sprintf("netns-%s-%s", pid, interfaceName)
		src, err := NewTcpPacketSource(name, "", interfaceName, packetCapture)

		if err != nil {
			log.Printf("Error listening to PID %s - %v", pid, err)
			errors <- err
			return
		}

		if err := netns.Set(oldnetns); err != nil {
			log.Printf("Unable to set back netns of current thread %v", err)
			errors <- err
			return
		}

		done <- src
	}(done)

	select {
	case err := <-errors:
		return nil, err
	case source := <-done:
		return source, nil
	}
}
