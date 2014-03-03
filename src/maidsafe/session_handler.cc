/*  Copyright 2014 MaidSafe.net limited

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

#include "maidsafe/session_handler.h"

#include "maidsafe/common/crypto.h"

namespace maidsafe {

namespace detail {

Identity GetSessionLocation(const passport::detail::Keyword& keyword,
                                   const passport::detail::Pin& pin) {
  return Identity(crypto::Hash<crypto::SHA512>(keyword.Hash<crypto::SHA512>().string() +
                                               pin.Hash<crypto::SHA512>().string()));
}

crypto::AES256Key SecureKey(const crypto::SecurePassword& secure_password) {
  return crypto::AES256Key(secure_password.string().substr(0, crypto::AES256_KeySize));
}

crypto::AES256InitialisationVector SecureIv(const crypto::SecurePassword& secure_password) {
  return crypto::AES256InitialisationVector(
      secure_password.string().substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
}

// TODO move to utility file
crypto::SecurePassword CreateSecureTmidPassword(const passport::detail::Password& password,
                                                const passport::detail::Pin& pin) {
  crypto::Salt salt(crypto::Hash<crypto::SHA512>(pin.Hash<crypto::SHA512>() + password.string()));
  assert(pin.Value() <= std::numeric_limits<uint32_t>::max());
  return crypto::CreateSecurePassword<passport::detail::Password>(password,
                                                                  salt,
                                                                  static_cast<uint32_t>(pin.Value()));
}

// TODO move to utility file
NonEmptyString XorData(const passport::detail::Keyword& keyword,
                       const passport::detail::Pin& pin,
                       const passport::detail::Password& password,
                       const NonEmptyString& data) {
  assert(pin.Value() <= std::numeric_limits<uint32_t>::max());
  uint32_t pin_value(static_cast<uint32_t>(pin.Value()));
  uint32_t rounds(pin_value / 2 == 0 ? (pin_value * 3) / 2 : pin_value / 2);
  std::string obfuscation_str = crypto::CreateSecurePassword<passport::detail::Keyword>(
      keyword,
      crypto::Salt(crypto::Hash<crypto::SHA512>(password.string() + pin.Hash<crypto::SHA512>())),
      rounds).string();
  // make the obfuscation_str of same size for XOR
  if (data.string().size() < obfuscation_str.size()) {
    obfuscation_str.resize(data.string().size());
  } else if (data.string().size() > obfuscation_str.size()) {
    obfuscation_str.reserve(data.string().size());
    while (data.string().size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(data.string().size());
  }
  return NonEmptyString(crypto::XOR(data.string(), obfuscation_str));
}

}  // namspace detail

}  // namespace maidsafe
