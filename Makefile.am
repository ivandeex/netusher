EXTRA_DIST = autogen.sh

SUBDIRS=src

release : dist ./release.sh
	./release.sh

perl-encode-setup:
	perl -MEncode::ConfigLocal -e1 || enc2xs -C

