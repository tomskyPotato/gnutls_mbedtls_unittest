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

# Include any dependencies generated for this target.
include mbedtls/programs/util/CMakeFiles/strerror.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include mbedtls/programs/util/CMakeFiles/strerror.dir/compiler_depend.make

# Include the progress variables for this target.
include mbedtls/programs/util/CMakeFiles/strerror.dir/progress.make

# Include the compile flags for this target's objects.
include mbedtls/programs/util/CMakeFiles/strerror.dir/flags.make

mbedtls/programs/util/CMakeFiles/strerror.dir/codegen:
.PHONY : mbedtls/programs/util/CMakeFiles/strerror.dir/codegen

mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj: mbedtls/programs/util/CMakeFiles/strerror.dir/flags.make
mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj: mbedtls/programs/util/CMakeFiles/strerror.dir/includes_C.rsp
mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj: C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/programs/util/strerror.c
mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj: mbedtls/programs/util/CMakeFiles/strerror.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj"
	cd /d C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util && C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj -MF CMakeFiles\strerror.dir\strerror.c.obj.d -o CMakeFiles\strerror.dir\strerror.c.obj -c C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\mbedtls\programs\util\strerror.c

mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/strerror.dir/strerror.c.i"
	cd /d C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util && C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\mbedtls\programs\util\strerror.c > CMakeFiles\strerror.dir\strerror.c.i

mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/strerror.dir/strerror.c.s"
	cd /d C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util && C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\mbedtls\programs\util\strerror.c -o CMakeFiles\strerror.dir\strerror.c.s

# Object files for target strerror
strerror_OBJECTS = \
"CMakeFiles/strerror.dir/strerror.c.obj"

# External object files for target strerror
strerror_EXTERNAL_OBJECTS = \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/asn1_helpers.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/bignum_codepath_check.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/bignum_helpers.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/hash.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/platform_builtin_keys.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_aead.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_asymmetric_encryption.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_cipher.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_key_agreement.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_key_management.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_mac.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_pake.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_signature.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/fake_external_rng_for_test.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/helpers.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_crypto_helpers.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_crypto_stubs.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_exercise_key.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_memory_poisoning_wrappers.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/random.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/test_memory.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/threading_helpers.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/tests/src/certs.c.obj" \
"C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/CMakeFiles/mbedtls_test.dir/tests/src/psa_test_wrappers.c.obj"

mbedtls/programs/util/strerror.exe: mbedtls/programs/util/CMakeFiles/strerror.dir/strerror.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/asn1_helpers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/bignum_codepath_check.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/bignum_helpers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/hash.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/platform_builtin_keys.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_aead.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_asymmetric_encryption.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_cipher.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_key_agreement.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_key_management.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_mac.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_pake.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/drivers/test_driver_signature.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/fake_external_rng_for_test.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/helpers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_crypto_helpers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_crypto_stubs.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_exercise_key.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/psa_memory_poisoning_wrappers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/random.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/test_memory.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/framework/tests/src/threading_helpers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/tests/src/certs.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/CMakeFiles/mbedtls_test.dir/tests/src/psa_test_wrappers.c.obj
mbedtls/programs/util/strerror.exe: mbedtls/programs/util/CMakeFiles/strerror.dir/build.make
mbedtls/programs/util/strerror.exe: mbedtls/library/libmbedcrypto.a
mbedtls/programs/util/strerror.exe: mbedtls/3rdparty/everest/libeverest.a
mbedtls/programs/util/strerror.exe: mbedtls/3rdparty/p256-m/libp256m.a
mbedtls/programs/util/strerror.exe: mbedtls/programs/util/CMakeFiles/strerror.dir/linkLibs.rsp
mbedtls/programs/util/strerror.exe: mbedtls/programs/util/CMakeFiles/strerror.dir/objects1.rsp
mbedtls/programs/util/strerror.exe: mbedtls/programs/util/CMakeFiles/strerror.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable strerror.exe"
	cd /d C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\strerror.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
mbedtls/programs/util/CMakeFiles/strerror.dir/build: mbedtls/programs/util/strerror.exe
.PHONY : mbedtls/programs/util/CMakeFiles/strerror.dir/build

mbedtls/programs/util/CMakeFiles/strerror.dir/clean:
	cd /d C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util && $(CMAKE_COMMAND) -P CMakeFiles\strerror.dir\cmake_clean.cmake
.PHONY : mbedtls/programs/util/CMakeFiles/strerror.dir/clean

mbedtls/programs/util/CMakeFiles/strerror.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\mbedtls\programs\util C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util C:\Users\tomsk\OneDrive\Dokumente\Software\gnutls_mbedtls_unittest\build\mbedtls\programs\util\CMakeFiles\strerror.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : mbedtls/programs/util/CMakeFiles/strerror.dir/depend

