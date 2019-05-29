package NetFlow

import (
	"fmt"
	"strconv"
	"encoding/json"
	"net"
	"time"
)

const IPV4_SRC_ADDR  = 8
const IPV4_DST_ADDR  = 12
const PROTOCOL = 4
const INBYTES = 1
const OUTPUTBYTES = 23
const INITIATOR_OCTETS = 231
const RESPONDER_OCTETS = 232
const SOURCE_PORT = 7
const DSTPORT = 11

type JSONData struct {
	DeviceIP string `json:"deviceip"`
	FlowDataUnixTime string `json:"flowdataunixtime"`
	SRC_ip string `json:"srcip"`
	DST_ip string `json:"dstip"`
	Protocol string `json:"protocol"`
	SRC_port string `json:"srcport"`
	DST_port string `json:"dstport"`
	RX_bytes string `json:"rxbytes"`
	TX_bytes string `json:"txbytes"`
}

type Netflowheader struct{
	VerH byte
	VerL byte
	Count uint16
	SystemUpTimeInt32 uint32
	UnixSecondsInt32  uint32
	PackageSequence uint32
	SourceID uint32
}

type FieldRec struct {
	FType uint16
	FLenght uint16
}

type FlowsetTemplete struct {
	FieldCount uint16
	Fields []FieldRec
}

type Rawflow struct {
	Rawflowdata []byte
}

type rawflows struct {
	Rawflowsdata []Rawflow
}

func TempletePaceInside(dataf []byte)(error int,templetemap []FieldRec){
	var retmap []FieldRec
	retmap = make([]FieldRec,0)
	if len(dataf) < 4 {
		return 1, nil
	}
	if len(dataf)%2 != 0 {
		return 2, nil
	}
	mindex := 0
	var ftype,flenght uint16

	for mindex < len(dataf){
		ftype = uint16(dataf[mindex+1])
		ftype |= uint16(dataf[mindex]) << 8
		flenght = uint16(dataf[mindex+3])
		flenght |= uint16(dataf[mindex+2]) << 8
		retmap = append(retmap,FieldRec{FType:ftype,FLenght:flenght})
		mindex = mindex + 4
	}

	return 0, retmap
}

func parcetemplete(data []byte,tmap *map[uint16]FlowsetTemplete){
	var alllenght uint16
	alllenght = uint16(data[3])
	alllenght |= uint16(data[2]) << 8

	var bindex uint16
	var eindex uint16
	bindex = 4
	eindex = 4



	var fcount uint16
	fcount = uint16(data[7])
	fcount |= uint16(data[6]) << 8

	var tdata1 []byte
	var TTempleteID uint16
	var FlowTemplete FlowsetTemplete
	if alllenght > 0 {
		for {

			TTempleteID = uint16(data[bindex+1])
			TTempleteID |= uint16(data[bindex]) << 8
			FlowTemplete.FieldCount = uint16(data[bindex+3])
			FlowTemplete.FieldCount |= uint16(data[bindex+2]) << 8


			bindex = bindex+4
			eindex = bindex + FlowTemplete.FieldCount*4
			if int(eindex) < len(data) {
				tdata1 = data[bindex:eindex]
				_,FlowTemplete.Fields =  TempletePaceInside(tdata1)
				(*tmap)[TTempleteID] = FlowTemplete
			}else{
				tdata1 = data[bindex:eindex]
				_,FlowTemplete.Fields =  TempletePaceInside(tdata1)
				(*tmap)[TTempleteID] = FlowTemplete
				break
			}

			bindex = eindex
		}
	}
}

func decodedata(data []byte,templeteid uint16, tmap *map[uint16]FlowsetTemplete)rawflows{
	var flowsize uint16
	flowsize = 0

	for _,Aelm := range (*tmap)[templeteid].Fields{
		flowsize = flowsize+Aelm.FLenght
	}

	var rawfd rawflows
	var oneflowsind, onefloweind uint16
	rawfd.Rawflowsdata = make([]Rawflow,0)
	oneflowsind = 4
	onefloweind = oneflowsind + flowsize

	var tbs1 []byte
	fend := false

	for {
		if onefloweind < uint16(len(data)){
			tbs1 = data[oneflowsind:onefloweind]
		}else {
			tbs1 = data[oneflowsind:]
			fend = true
		}

		oneflowsind = onefloweind
		onefloweind = onefloweind + flowsize

		if fend{
			break
		}
		rawfd.Rawflowsdata = append(rawfd.Rawflowsdata,Rawflow{tbs1})
	}

	return rawfd

}

func convertbytestouint(buffer []byte)uint32{
	var uiresult uint32 = 0
	var offsett uint = 1
	for bcbytes := len(buffer)-1; bcbytes >= 0; bcbytes--{
		if bcbytes == len(buffer)-1{
			uiresult = uint32(buffer[bcbytes])
		}else {
			uiresult |= uint32(buffer[bcbytes]) << (8*offsett)
			offsett++
		}
	}
	return uiresult
}

func StartCollector(listenip string,listenport string){
	var FTemplete map[uint16]FlowsetTemplete
	FTemplete = make(map[uint16]FlowsetTemplete,0)
	pc,err := net.ListenPacket("udp",listenip+":"+listenport)

	var protocols = map[uint16]string{
		1:"icmp",
		2:"igmp",
		6:"tcp",
		17:"udp",
	}

	if err != nil{
		fmt.Print(err)
	}
	defer pc.Close()
	RXBuffer := make([]byte,2000)
	for{
		fp,faip,_ := pc.ReadFrom(RXBuffer)
		countf := convertbytestouint(RXBuffer[2:4])
		suptime := convertbytestouint(RXBuffer[4:8])
		unixseconds := convertbytestouint(RXBuffer[8:12])
		packagesequence := convertbytestouint(RXBuffer[12:16])
		sourceid := convertbytestouint(RXBuffer[16:20])


		NH := Netflowheader{VerH:RXBuffer[0],VerL:RXBuffer[1], Count: uint16(countf), SystemUpTimeInt32:suptime,UnixSecondsInt32:unixseconds,PackageSequence:packagesequence,SourceID:sourceid}
		uttm := time.Unix(int64(NH.UnixSecondsInt32),0)

		llenght := NH.Count
		DataIndex := 20 //offsett from start packet to data fields
		cpind := true
		var FlowSetID uint16
		for cpind {
			var currentflenght uint16
			FlowSetID = uint16(RXBuffer[DataIndex + 1])
			FlowSetID |= uint16(RXBuffer[DataIndex]) << 8
			currentflenght = uint16(RXBuffer[DataIndex+3])
			currentflenght |= uint16(RXBuffer[DataIndex+2])<<8
			lastindex := DataIndex+int(currentflenght)
			var flowdata []byte
			if lastindex < fp{
				flowdata = RXBuffer[DataIndex:lastindex]
			}else{
				flowdata = RXBuffer[DataIndex:lastindex]
			}

			if FlowSetID == 0 {
				parcetemplete(flowdata,&FTemplete)
			}else {
				_,ok := FTemplete[FlowSetID]
				if ok {
					rdt1 := decodedata(flowdata,FlowSetID,&FTemplete)


					for _,flowdata := range rdt1.Rawflowsdata {
						var jsd JSONData
						var starti,endi uint16
						var pdata []byte
						starti = 0
						endi = 0
						jsd.DeviceIP = faip.String()
						jsd.FlowDataUnixTime = uttm.String()
						for _,s := range FTemplete[FlowSetID].Fields{
							endi = starti+s.FLenght
							if endi < uint16(len(flowdata.Rawflowdata)){
								pdata = flowdata.Rawflowdata[starti:endi]
							}else{
								pdata = flowdata.Rawflowdata[starti:]
							}
							protostring := ""

							switch s.FType{
							case IPV4_SRC_ADDR:
								jsd.SRC_ip = net.IP(pdata).String()
							case IPV4_DST_ADDR:
								jsd.DST_ip = net.IP(pdata).String()
							case INITIATOR_OCTETS:
								jsd.TX_bytes = strconv.Itoa(int(convertbytestouint(pdata)));break
							case RESPONDER_OCTETS:
								jsd.RX_bytes = strconv.Itoa(int(convertbytestouint(pdata)));break
							case PROTOCOL: _,pexist := protocols[uint16(pdata[0])];if pexist{
								protostring = protocols[uint16(pdata[0])]
							};
								jsd.Protocol = protostring;break
							case SOURCE_PORT:
								jsd.SRC_port = strconv.Itoa(int(convertbytestouint(pdata)));break
							case DSTPORT:
								jsd.DST_port = strconv.Itoa(int(convertbytestouint(pdata)));break
							default: break
							}
							starti = endi
						}
						Jsontext,_ := json.Marshal(&jsd)
						fmt.Println(string(Jsontext))
					}

				}
			}

			if lastindex >= fp-1{
				cpind = false
			}
			llenght = llenght-1
			DataIndex = DataIndex + int(currentflenght)
		}
	}
}