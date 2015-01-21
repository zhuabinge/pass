#!/bin/bash
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin;
export PATH
cycle=1
Inte=$(ls /sys/class/net)


function CPU {
	IDLE=$(awk '/\<cpu\>/{print $2" "$3" "$4" "$5" "$6" "$7" "$8}' /proc/stat | awk '{print $4}')
	Total=$(awk '/\<cpu\>/{print $2" "$3" "$4" "$5" "$6" "$7" "$8}' /proc/stat | awk '{print $1+$2+$3+$4+$5+$6+$7}')
	echo $IDLE $Total
}
function Memory {
	Mem=$(free | grep Mem: | awk '{print $3/$2*100}')
	echo $Mem
}
function Traffic {
	Inte_Name=$1
	RX=$(cat /proc/net/dev | grep $Inte_Name | tr : " " | awk '{print $2}')
	TX=$(cat /proc/net/dev | grep $Inte_Name | tr : " " | awk '{print $10}')
	echo $RX $TX
}
function Main {
	CPU_IDLE_S=$(CPU | awk '{print $1}')
  	CPU_Total_S=$(CPU | awk '{print $2}')
	for Name in $Inte
	do
		RX_Name=$Name'_RX_S'
		TX_Name=$Name'_TX_S'
		eval $RX_Name=$(Traffic $Name | awk '{print $1}')
		eval $TX_Name=$(Traffic $Name | awk '{print $2}')
   	done
	sleep $cycle
  	CPU_IDLE_E=$(CPU | awk '{print $1}')
  	CPU_Total_E=$(CPU | awk '{print $2}')
	for Name in $Inte
	do
		RX_Name=$Name'_RX_E'
		TX_Name=$Name'_TX_E'
		eval $RX_Name=$(Traffic $Name | awk '{print $1}')
		eval $TX_Name=$(Traffic $Name | awk '{print $2}')

		eval $Name'_RX'=$(eval echo \$$Name'_RX_E' \$$Name'_RX_S' | awk '{print $1-$2}')
		eval $Name'_TX'=$(eval echo \$$Name'_TX_E' \$$Name'_TX_S' | awk '{print $1-$2}')
		eval echo $Name:\$$Name'_RX':\$$Name'_TX'
   	done
   	CPU_IDLE=$(expr $CPU_IDLE_E - $CPU_IDLE_S)
   	CPU_Total=$(expr $CPU_Total_E - $CPU_Total_S)
   	CPU_Rate=$(expr 1-$CPU_IDLE/$CPU_Total | bc -l)
   	CPU_SYS=$(expr $CPU_Rate*100 | bc -l)
   	CPU=$(expr "scale=1; $CPU_SYS/1" | bc)
   	Mem_SYS=$(free | grep Mem | awk '{print ($3/$2)*100}')
   	Mem=$(expr "scale=1; $Mem_SYS/1" | bc)
	echo CPU:$CPU
	echo Mem:$Mem
}
function push_resolve {
   redis-cli publish sysinfoUpdate $1
	#echo redis-cli publish sysinfo-update $1
}

while [ "1" ]
  do
  	resolve=$(Main | tr -s "\n" "|")
  	push_resolve ${resolve%|}
  done

