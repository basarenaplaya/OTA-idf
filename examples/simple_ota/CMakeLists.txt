# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Tell ESP-IDF where to find our components
set(EXTRA_COMPONENT_DIRS "../../components;$ENV{IDF_PATH}/examples/common_components/protocol_examples_common")

project(simple_ota)

idf_build_set_property(COMPILE_OPTIONS "-Wno-error=all" APPEND)
