#==================================================================================================#
#                                                                                                  #
#  Copyright 2014 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

project(api)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(ApiSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe)
ms_glob_dir(Api ${ApiSourcesDir} Api)
ms_glob_dir(ApiDetail ${ApiSourcesDir}/detail "Api Detail")

# Tests
set(TESTS_MAIN_CC ${ApiSourcesDir}/tests/tests_main.cc)
source_group("Tests Source Files" FILES ${TESTS_MAIN_CC}
            # Append more test files here
            )

#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(maidsafe_api_detail ${ApiDetailAllFiles})
ms_add_static_library(maidsafe_api ${ApiAllFiles})
target_include_directories(maidsafe_api_detail PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(maidsafe_api PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_api_detail maidsafe_drive maidsafe_nfs_client maidsafe_nfs_vault ${BoostRegexLibs})
target_link_libraries(maidsafe_api maidsafe_api_detail maidsafe_vault)

if(MaidsafeTesting)
  ms_add_executable(TESTapi "Tests/Api" ${TESTS_MAIN_CC})
  target_include_directories(TESTapi PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(TESTapi maidsafe_api)
endif()

ms_rename_outdated_built_exes()


#==================================================================================================#
# Export detail                                                                                    #
#==================================================================================================#

#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)


#==================================================================================================#
# Export API Dependency paths for UI projects                                                   #
#==================================================================================================#


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  ms_add_style_test()
  ms_add_gtests(TESTapi)
  ms_add_project_experimental()
  ms_test_summary_output()
endif()
