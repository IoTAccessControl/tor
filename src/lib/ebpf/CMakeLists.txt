cmake_minimum_required(VERSION 3.14)

project(libebpf VERSION 0.1 LANGUAGES C)

option(DEBUG "DEBUG BUILD" ON)

if (DEBUG) 
	add_compile_options(-g -fsanitize=address)
	add_link_options(-g -fsanitize=address)
endif()

# set cmake output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# libebpf static library
file(GLOB libsrc
	${CMAKE_CURRENT_SOURCE_DIR}/*.h
	${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(${PROJECT_NAME} STATIC
		${libsrc})

# Demo Exe
file(GLOB demo_src ${CMAKE_CURRENT_SOURCE_DIR}/ewfd-defense/test/*.c
		${CMAKE_CURRENT_SOURCE_DIR}/ewfd-defense/src/*.c)

add_executable(test ${demo_src})
target_include_directories(test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/)
target_include_directories(test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ewfd-defense/src)
target_link_libraries(test PUBLIC ${PROJECT_NAME})