/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_TESTS_TEST_UTILS_H_
#define MAIDSAFE_TESTS_TEST_UTILS_H_

#include <string>
#include <tuple>

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/authentication/user_credentials.h"

namespace maidsafe {

namespace test {

std::tuple<std::string, uint32_t, std::string> GetRandomUserCredentialsTuple();

authentication::UserCredentials GetRandomUserCredentials();

authentication::UserCredentials MakeUserCredentials(
  const std::tuple<std::string, uint32_t, std::string>& credentials_tuple);

template <typename ErrorCodeEnum>
testing::AssertionResult ThrowsAs(std::function<void()> statement,
                                  ErrorCodeEnum expected_error_code_value) {
  static_assert(std::is_error_code_enum<ErrorCodeEnum>::value, "This must be an error code enum.");
  std::error_code expected_code{ make_error_code(expected_error_code_value) };
  std::ostringstream failure_message;
  failure_message << "expected exception \"" << expected_code << "\" with message \""
                  << expected_code.message() << "\", but it threw ";
  try {
    statement();
    failure_message << "nothing";
  }
  catch (const maidsafe_error& error) {
    if (expected_code == error.code())
      return testing::AssertionSuccess();
    else
      failure_message << "\"" << error.code() << "\" with message \"" << error.what() << "\"";
  }
  catch (const std::exception& e) {
    failure_message << "a std::exception with message \"" << e.what() << "\"";
  }
  catch (...) {
    failure_message << "a different non-std:: exception";
  }
  return testing::AssertionFailure() << failure_message.str();
}

}  // namespace test

namespace detail {

namespace test {

std::tuple<std::string, uint32_t, std::string> GetRandomUserCredentialsTuple();

authentication::UserCredentials GetRandomUserCredentials();

authentication::UserCredentials MakeUserCredentials(
    const std::tuple<std::string, uint32_t, std::string>& credentials_tuple);

}  // namespace test

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_TESTS_TEST_UTILS_H_
