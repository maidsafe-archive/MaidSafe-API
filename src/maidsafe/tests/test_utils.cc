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

#include "maidsafe/tests/test_utils.h"

#include <string>

#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"

namespace maidsafe {

namespace test {

std::tuple<std::string, uint32_t, std::string> GetRandomUserCredentialsTuple() {
  std::string keyword_str{ RandomAlphaNumericString((RandomUint32() % 100) + 1) };
  uint32_t pin_value{ RandomUint32() };
  std::string password_str{ RandomAlphaNumericString((RandomUint32() % 100) + 1) };
  return std::tuple<std::string, uint32_t, std::string>(keyword_str, pin_value, password_str);
}

authentication::UserCredentials GetRandomUserCredentials() {
  return MakeUserCredentials(GetRandomUserCredentialsTuple());
}

authentication::UserCredentials MakeUserCredentials(
  const std::tuple<std::string, uint32_t, std::string>& user_credentials_tuple) {
  authentication::UserCredentials user_credentials;
  user_credentials.keyword = maidsafe::make_unique<authentication::UserCredentials::Keyword>(
          std::get<0>(user_credentials_tuple));
  user_credentials.pin = maidsafe::make_unique<authentication::UserCredentials::Pin>(
          std::to_string(std::get<1>(user_credentials_tuple)));
  user_credentials.password = maidsafe::make_unique<authentication::UserCredentials::Password>(
          std::get<2>(user_credentials_tuple));
  return user_credentials;
}

}  // namespace test

}  // namespace maidsafe
