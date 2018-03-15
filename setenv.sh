#!/bin/sh
ARG=32
#case `isainfo -k` in
#i386|sparc) ARG=32;;
#amd64|sparcv9) ARG=64;;
#esac
case `uname -m` in
x86_64|amd64) ARG=64;;
esac
for i in $*
do
	case $i in
	--64) ARG=64;;
	--32) ARG=32;;
	--help|--usage) echo "Usage: setenv.sh options" >&2
		echo "--32 - configure 32bit environbent" >&2
		echo "--64 - configure 64bit environment" >&2
		exit 1;;
	esac
done

LIBDIR64=`echo /opt/cprocsp/lib/amd64 |sed -e 's/ia32/amd64/g;s/ppc$/ppc64/g;s/sparc$/sparcv9/g'`
LIBDIR32=`echo /opt/cprocsp/lib/amd64 |sed -e 's/amd64/ia32/g;s/ppc64/ppc/g;s/sparcv9/sparc/g'`

if test x$ARG = x64;then
MODVERSFILE=/opt/cprocsp/include/Module.symvers.amd64
else
MODVERSFILE=/opt/cprocsp/include/Module.symvers.ia32
fi

if test x$ARG = x64
then
    libdir=$LIBDIR64
    SIZEOF_VOID_P=8
else
    libdir=$LIBDIR32
    SIZEOF_VOID_P=4
fi

add_CPPFLAGS=
test -f /usr/include/stdint.h && \
    add_CPPFLAGS="${add_CPPFLAGS} -DHAVE_STDINT_H"
test -f /usr/include/sys/inttypes.h && \
    add_CPPFLAGS="${add_CPPFLAGS} -DHAVE_SYS_INTTYPES_H"

if test -z "$CXX" && test -z "$CCC";then
    echo "No compiler specified... trying to guess" >&2
    case `uname -s` in
#    SunOS) case `isainfo -k` in
    SunOS) case "XXX" in
#for stupid lsb checkers "XXX" (instead of isainfo -k)
	       amd64) COMPARCH=amd64
		      test $ARG = 64 && CSP_KERNEL_FLAGS="-DUSE_STD_MM -xmodel=kernel";;
	       sparcv9) COMPARCH=v9
			CSP_KERNEL_FLAGS="-DUSE_STD_MM";;

	   esac
	   if test -f /opt/SUNWspro/bin/CC;then
	        echo "Studio is found">&2
		CCC=/opt/SUNWspro/bin/CC
	   elif type CC >/dev/null;then 
		echo "CC is in the path" >&2
		CCC=CC
	   elif type g++ >/dev/null;then
		echo "g++ is found">&2
		CCC=g++
	   else
		echo "No C++  found">&2
		exit 1
           fi		
	   test x$ARG = x64 && case $CCC in
	    *CC) case `$CCC -V 2>&1|head -1|cut -d' ' -f4` in
		    5.9) echo "ARCH_FLAGS=\"-m64\";export ARCH_FLAGS;";;
		    *) echo "ARCH_FLAGS=\"-xarch=$COMPARCH\";export ARCH_FLAGS;";;
		 esac
		 test -n "$CSP_KERNEL_FLAGS" && echo "CSP_KERNEL_FLAGS=\"$CSP_KERNEL_FLAGS\";export CSP_KERNEL_FLAGS;"
		 ;;
	    *) CCC="$CCC -m64";;
	   esac
	   echo "CCC=\"$CCC\";export CCC;"
	   if test -f /opt/SUNWspro/bin/cc;then
	        echo "Studio is found">&2
		CC=/opt/SUNWspro/bin/cc
	   elif type cc >/dev/null;then 
		echo "cc is in the path" >&2
		CC=cc
	   elif type gcc >/dev/null;then
		echo "gcc is found">&2
		CC=gcc
	   else
		echo "Nothing is found">&2
		exit 1
           fi
	   echo "CC=\"$CC\";export CC;" ;;		

    AIX)
	if test x$ARG = x32;then
	    echo "CXX=/usr/vacpp/bin/xlC;export CXX;"
	    echo "CC=\"/usr/vac/bin/cc -qlanglvl=extc89 -qlanglvl=extc99\";export CC;"
	else
	    echo "CXX=\"/usr/vacpp/bin/xlC -q64\";export CXX;"
	    echo "CC=\"/usr/vac/bin/cc -q64 -qlanglvl=extc89 -qlanglvl=extc99\";export CC;"
	    echo "OBJECT_MODE=64;export OBJECT_MODE;"
	fi
    ;;
    *) 
	if type g++ >/dev/null;then
          echo "g++ found in the path" >&2
	  if ( test `uname -m` = x86_64 || test `uname -s` = Darwin ) && test x$ARG = x32
          then
                echo "CC=\"gcc -m32\";export CC;"
                echo "CXX=\"g++ -m32\";export CXX;"
		echo "ARCH_FLAGS=\"-m32\";export ARCH_FLAGS;"
	  else
                echo "CC=\"gcc\";export CC;"
                echo "CXX=\"g++\";export CXX;"
          fi
	  if test x$ARG = x32
	  then
		echo "LSB_LD=/lib/ld-lsb.so.3;export LSB_LD;"
	  else
		echo "LSB_LD=/lib64/ld-lsb-x86-64.so.3;export LSB_LD;"
	  fi
	else
          if type clang++ >/dev/null; then
            echo "clang++ found in the path" >&2
            echo "CC=\"clang\";export CC;"
            echo "CXX=\"clang++\";export CXX;"
          else
            echo "Nothing is found">&2
            exit 1
          fi
	fi;;
    esac
fi    
if test -z "$INSTALL"
then 
    if type install >/dev/null;then
	INSTALL=install
    else
	INSTALL=cp
    fi
fi
prefix=/opt/cprocsp
includedir=${prefix}/include
if test -z "$includedir"
then
includedir=/opt/cprocsp/include
fi

echo "CSP_DIR=/opt/cprocsp;"
echo "CSP_INCLUDE=$includedir;"
echo "add_CPPFLAGS=\"$add_CPPFLAGS\";"
echo "SIZEOF_VOID_P=$SIZEOF_VOID_P;"
echo "CSP_LIB=$libdir;"
echo "INSTALL=$INSTALL;"
echo "MODVERSFILE=$MODVERSFILE;"
case `uname -s` in
SunOS)echo "CSP_EXTRA_LIBS=\"-R$libdir -lsocket -lnsl\";";;
FreeBSD)echo "CSP_EXTRA_LIBS=\"-R$libdir -lpthread\";";;
AIX)echo "CXXFLAGS=\"$CXXFLAGS -qlang=stdc99\";export CXXFLAGS"
echo "add_ldflags=\"-Wl,-brtl\";";;
Darwin) echo "CSP_EXTRA_LIBS=\"-lpthread -framework CoreFoundation\";";;
*) echo "CSP_EXTRA_LIBS=\"-lpthread\";";;
esac
echo "export CSP_DIR CSP_INCLUDE CSP_LIB CSP_EXTRA_LIBS SIZEOF_VOID_P INSTALL add_ldflags add_CPPFLAGS MODVERSFILE;"
