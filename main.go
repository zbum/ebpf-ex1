package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
    // RemoveMemlock 함수는 현행 프로세스가 RAM에 lock할 수 있는 메모리양의 제한을 제거합니다.
	// cgroup 기반의 메모리 계산 방식을 사용하기 때문에, kernel version 5.11 이상 버전에서는 필요하지 않습니다. (커널 버전은 uname -r 로 확인할 수 있습니다.)
	// 최신 버전에서는 아무런 기능을 하지 않습니다.
	//
	// 함수는 전역 프로세스별 제한을 변경할 수 있기 때문에 이 함수는 프로그램 시작할때 실행해야 합니다. 
	// 
	// 이 함수는 편의를 위한 것이고 RLIMIT_MEMLOCK를 영구적인 무한대로 설정하는 것이 적절한 경우에 사용해야 합니다. 
	// 원한다면, 더 타당한 제한을 가진 prlimit를 직접 실행하는 것을 고려하세요.

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// 컴파일한 eBPF ELF를 로드하고 이것을 커널에 로드합니다.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "enp3s0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
