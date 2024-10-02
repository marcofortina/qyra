# Copyright (c) 2024 Marco Fortina
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

# Set aclocal flags to include macros from the 'build-aux/m4' directory
ACLOCAL_AMFLAGS = -I build-aux/m4

# Specify subdirectories to build, in this case, the 'src' directory
SUBDIRS = src

# Define the directory for pkg-config files and specify the file to install
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libqyra.pc

# Specify the documentation files to install with 'make install'
dist_doc_DATA = README.md LICENSE doc/API.md

# Custom script for generating files, but not installed
dist_noinst_SCRIPTS = autogen.sh

# Include all files inside doc/doxygen in the distribution tarball
EXTRA_DIST = \
	$(wildcard contrib/*) \
	$(wildcard doc/*) \
	$(wildcard examples/*)

# Rule to generate the Doxygen documentation
doc/doxygen/.stamp: doc/Doxyfile
	$(MKDIR_P) $(@D)
	$(DOXYGEN) $^
	$(AM_V_at) touch $@

# If Doxygen is available, build the documentation
if HAVE_DOXYGEN
docs: doc/doxygen/.stamp

# Target to clean up the documentation directory
clean-docs:
	@echo "Cleaning documentation files..."
	rm -rf doc/doxygen

# Custom rule to install the entire 'doc' directory
install-data-local: docs
	$(MKDIR_P) $(DESTDIR)$(docdir)
	cp -r doc/doxygen/html $(DESTDIR)$(docdir)

# Remove the installed documentation directory during uninstallation.
uninstall-local:
	-rm -rf $(DESTDIR)$(docdir)/html

# Ensure that make docs is run when creating a distribution
dist-hook:
	$(MAKE) docs

else
docs:
	@echo "error: doxygen not found"
clean-docs:
	@echo "error: doxygen not found"
endif

# Custom clean rule to clean both docs and dist/ directory
clean-local: clean-docs
	@echo "Cleaning dist directory..."
	rm -rf dist/

# Target to invoke tests from the top-level directory
# Delegates the test execution to the src directory
test:
	$(MAKE) -C src test

# Target to invoke benchmarks from the top-level directory
# Delegates the benchmarks execution to the src directory
bench:
	$(MAKE) -C src bench