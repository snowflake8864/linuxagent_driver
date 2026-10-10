#!/bin/bash

set -e
set -x

KVR="`uname -r`"
OPTPATH="/opt/osecforcnos/Data"
VMLINUX="/boot/vmlinux-$KVR"
SYSMAP="System.map-$KVR"
KALLSYMS="/proc/kallsyms"
LINKSYM="$OPTPATH/syms"

link_syms()
{
	if [ -f "$VMLINUX" ];then
		nm "$VMLINUX" |egrep -w "sys_close|security_ops|security_hold_heads|security_secondary_ops"  >"$OPTPATH/$SYSMAP"
		ln -s "$OPTPATH/$SYSMAP" "$LINKSYM"
	else
		if [ -f "/boot/$SYSMAP" ];
		then
			cat "/boot/$SYSMAP" |egrep -w "sys_close|security_ops|security_hold_heads|security_secondary_ops" >"$OPTPATH/$SYSMAP"
			ln -s "$OPTPATH/$SYSMAP" "$LINKSYM"
		elif [ -f "$KALLSYMS" ];
		then
			cat "$KALLSYMS" |egrep -w "sys_close|security_ops|security_hold_heads|security_secondary_ops" >"$OPTPATH/$SYSMAP"
			ln -s "$OPTPATH/$SYSMAP" "$LINKSYM"
		fi
	fi		
}

run()
{
	link_syms
}

run
