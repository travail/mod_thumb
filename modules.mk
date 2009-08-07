mod_thumb.la: mod_thumb.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_thumb.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_thumb.la
