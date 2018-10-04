#
# Copyright 2014 Trend Micro Incorporated
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/
#

#
# Fix these variables.
# * NOTE: Do not support user space here.
#
# * NOTE: Add vpath? Is't necessary?
#


#####

#
# CMD_FORBID_EMPTY_STR
# Compare two strings. Exit -1 if it's not equal.
# 1: input symbol (left value)
# 2: value of input symbol (right value)
# 3: Some more comment to display as error msg.
#
CMD_FORBID_EMPTY_STR = if [ "$(2)" = "" ]; then echo " * ERROR: Input string $(1) is empty." "$(3)"; exit -1; fi;

#
# CMD_MAKE_LINUX - A wrapper to run make on linux kernel (support cross compile)
# 1: Linux kernel source directory
# 2: This module directory
# 3: Kernel arch
# 4: Cross compiler prefix
# 5: Verbose level
# 6: Makefile target
#
CMD_MAKE_LINUX = $(MAKE) -C "$(1)" M=$(2) $(if $(3),ARCH=$(3)) $(if $(4),CROSS_COMPILE=$(4)) $(if $(5),V=$(5)) $(6)

#####

mod_name := ubnt_nf_app
mod_path := $(mod_name).ko

ifeq ($(KERNELRELEASE),) # Check if goals are from kernel or not.

export TDTS_KMOD_DIR ?= $(CURDIR)

include Makefile.cfg

all: prepare verify_kernel_dir kmod_build

.PHONY: prepare
prepare:
	@if [ -f $(TDTS_DIR_PACK_LIB)/$(core_mod_name) ]; then ln -sf $(TDTS_DIR_PACK_LIB)/$(core_mod_name) . ; fi
	@if [ -f $(PLAT_DIR)/tmcfg.h ]; then ln -sf $(PLAT_DIR)/tmcfg.h $(TDTS_DIR_PACK)/include/tdts  ; fi

.PHONY: verify_kernel_dir
verify_kernel_dir:
	@$(call CMD_FORBID_EMPTY_STR,TMCFG_KERN_DIR,$(TMCFG_KERN_DIR))
	@echo "...verify kernel directory: $(TMCFG_KERN_DIR) with arch $(TMCFG_KERN_ARCH)"
	@test -d $(TMCFG_KERN_DIR)

.PHONY: kmod_build
kmod_build: verify_kernel_dir
	@echo "...build kernel module at kernel dir '$(TMCFG_KERN_DIR)' from $(CURDIR)"
	@$(call CMD_MAKE_LINUX,$(TMCFG_KERN_DIR),$(CURDIR),$(TMCFG_KERN_ARCH),$(TMCFG_TC_PFX),$(if $(TMCFG_DBG_VERBOSE_CC_MSG),1),modules)

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	@echo "...clean object files by kernel dir '$(TMCFG_KERN_DIR)'"
	@$(call CMD_MAKE_LINUX,$(TMCFG_KERN_DIR),$(CURDIR),$(TMCFG_KERN_ARCH),$(TMCFG_TC_PFX),$(if $(TMCFG_DBG_VERBOSE_CC_MSG),1),clean)

else
#
# This's kbuild.
#

include $(TDTS_KMOD_DIR)/Makefile.cfg

obj-m := $(mod_name).o


include $(TDTS_KMOD_DIR)/kbuild.inc
$(mod_name)-objs += $(tdts-kmod-obj-y)

ifeq ($(TMCFG_E_CORE_USE_KBUILD),y)
$(mod_name)-objs += $(core_mod_name)
else
$(mod_name)-objs += $(core_ar_name)
endif

ccflags-y += $(TMCFG_E_EXTRA_CFLAGS)

endif

.PHONY: check
check:

.PHONY: install
install:
	INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=$(DESTDIR) \
		$(MAKE) ARCH=mips -C $(TMCFG_KERN_DIR) M=$(CURDIR) modules_install
	rm -f $(DESTDIR)/lib/modules/*/modules.*
