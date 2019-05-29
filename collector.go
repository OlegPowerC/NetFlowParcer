package main

import "NetFlow/NetFlow"

const ListenOnIp = "192.168.55.165"
const ListenOnPort = "9996"


func main() {
	NetFlow.StartCollector(ListenOnIp,ListenOnPort)
}
