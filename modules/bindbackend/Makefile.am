pkglib_LTLIBRARIES = libbindbackend.la
AM_CPPFLAGS += -I../../pdns

AM_LFLAGS = -i
AM_YFLAGS = -d --verbose --debug

BUILT_SOURCES = \
	../../pdns/bind-dnssec.schema.sqlite3.sql.h \
	../../pdns/bindlexer.l \
	../../pdns/bindparser.yy

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libbindbackend_la_SOURCES = \
	bindbackend2.cc bindbackend2.hh \
	binddnssec.cc \
	../../pdns/arguments.hh \
	../../pdns/backends/gsql/ssql.hh
	../../pdns/base32.hh \
	../../pdns/bindparserclasses.hh \
	../../pdns/dns.hh \
	../../pdns/dnsbackend.hh \
	../../pdns/dnspacket.hh \
	../../pdns/dnssecinfra.hh \
	../../pdns/dnsseckeeper.hh \
	../../pdns/dynlistener.hh \
	../../pdns/lock.hh \
	../../pdns/logger.hh \
	../../pdns/misc.hh \
	../../pdns/namespaces.hh
	../../pdns/qtype.hh \
	../../pdns/zoneparser-tng.hh

libbindbackend_la_LDFLAGS = -module -avoid-version

../../pdns/bind-dnssec.schema.sqlite3.sql.h: ../../pdns/bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' $< | sed 's/^/"/g'  ; echo ';' ) > $@

# for bindparser.h/hh
.hh.h:
	cp $< $@
