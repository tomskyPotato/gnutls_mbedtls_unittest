# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 4.0

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\CMake\bin\cmake.exe

# The command to remove a file.
RM = C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\CMake\bin\cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build

# Utility rule file for test_suite_psa_generated_data.

# Include any custom commands dependencies for this target.
include mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/compiler_depend.make

# Include the progress variables for this target.
include mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/progress.make

mbedtls/tests/CMakeFiles/test_suite_psa_generated_data: mbedtls/tests/suites/test_suite_psa_crypto_generate_key.generated.data
mbedtls/tests/CMakeFiles/test_suite_psa_generated_data: mbedtls/tests/suites/test_suite_psa_crypto_low_hash.generated.data
mbedtls/tests/CMakeFiles/test_suite_psa_generated_data: mbedtls/tests/suites/test_suite_psa_crypto_not_supported.generated.data
mbedtls/tests/CMakeFiles/test_suite_psa_generated_data: mbedtls/tests/suites/test_suite_psa_crypto_op_fail.generated.data
mbedtls/tests/CMakeFiles/test_suite_psa_generated_data: mbedtls/tests/suites/test_suite_psa_crypto_storage_format.current.data
mbedtls/tests/CMakeFiles/test_suite_psa_generated_data: mbedtls/tests/suites/test_suite_psa_crypto_storage_format.v0.data

mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/codegen:
.PHONY : mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/codegen

test_suite_psa_generated_data: mbedtls/tests/CMakeFiles/test_suite_psa_generated_data
test_suite_psa_generated_data: mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/build.make
.PHONY : test_suite_psa_generated_data

# Rule to build all files generated by this target.
mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/build: test_suite_psa_generated_data
.PHONY : mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/build

mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/clean:
	cd /d C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\tests && $(CMAKE_COMMAND) -P CMakeFiles\test_suite_psa_generated_data.dir\cmake_clean.cmake
.PHONY : mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/clean

mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\mbedtls\tests C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\tests C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\tests\CMakeFiles\test_suite_psa_generated_data.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : mbedtls/tests/CMakeFiles/test_suite_psa_generated_data.dir/depend

