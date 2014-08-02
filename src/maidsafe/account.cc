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

#include "maidsafe/account.h"

#include <utility>

#include "maidsafe/common/error.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/authentication/user_credential_utils.h"

#include "maidsafe/account.pb.h"

namespace maidsafe {

ImmutableData EncryptAccount(const authentication::UserCredentials& user_credentials,
                             Account& account) {
  protobuf::Account proto_account;
  proto_account.set_serialised_passport(account.passport->Encrypt(user_credentials)->string());
  proto_account.set_timestamp(GetTimeStamp());
  proto_account.set_ip(account.ip.to_string());
  proto_account.set_port(account.port);
  if (account.unique_user_id.IsInitialised())
    proto_account.set_unique_user_id(account.unique_user_id.string());
  if (account.root_parent_id.IsInitialised())
    proto_account.set_root_parent_id(account.root_parent_id.string());

  account.timestamp = TimeStampToPtime(proto_account.timestamp());

  NonEmptyString serialised_account{ proto_account.SerializeAsString() };
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return ImmutableData{ crypto::SymmEncrypt(
      authentication::Obfuscate(user_credentials, serialised_account),
      authentication::DeriveSymmEncryptKey(secure_password),
      authentication::DeriveSymmEncryptIv(secure_password)).data };
}

Account::Account() : passport(), timestamp(), ip(), port(0), unique_user_id(), root_parent_id() {}

Account::Account(const passport::MaidAndSigner& maid_and_signer)
    : passport(maidsafe::make_unique<passport::Passport>(maid_and_signer)),
      timestamp(), ip(), port(0), unique_user_id(), root_parent_id() {}

Account::Account(const ImmutableData& encrypted_account,
                 const authentication::UserCredentials& user_credentials)
    : passport(), timestamp(), ip(), port(0), unique_user_id(), root_parent_id() {
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  NonEmptyString serialised_account{
      authentication::Obfuscate(user_credentials,
          crypto::SymmDecrypt(crypto::CipherText{ encrypted_account.data() },
                              authentication::DeriveSymmEncryptKey(secure_password),
                              authentication::DeriveSymmEncryptIv(secure_password))) };

  protobuf::Account proto_account;
  if (!proto_account.ParseFromString(serialised_account.string()))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  crypto::CipherText encrypted_passport{ NonEmptyString(proto_account.serialised_passport()) };
  passport = maidsafe::make_unique<passport::Passport>(encrypted_passport, user_credentials);
  timestamp = TimeStampToPtime(proto_account.timestamp());
  ip = boost::asio::ip::address::from_string(proto_account.ip());
  port = static_cast<uint16_t>(proto_account.port());
  if (proto_account.has_unique_user_id())
    unique_user_id = Identity(proto_account.unique_user_id());
  if (proto_account.has_root_parent_id())
    root_parent_id = Identity(proto_account.root_parent_id());
}

Account::Account(Account&& other) MAIDSAFE_NOEXCEPT
    : passport(std::move(other.passport)),
      timestamp(std::move(other.timestamp)),
      ip(std::move(other.ip)),
      port(std::move(other.port)),
      unique_user_id(std::move(other.unique_user_id)),
      root_parent_id(std::move(other.root_parent_id)) {}

Account& Account::operator=(Account other) {
  swap(*this, other);
  return *this;
}

void swap(Account& lhs, Account& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.passport, rhs.passport);
  swap(lhs.timestamp, rhs.timestamp);
  swap(lhs.ip, rhs.ip);
  swap(lhs.port, rhs.port);
  swap(lhs.unique_user_id, rhs.unique_user_id);
  swap(lhs.root_parent_id, rhs.root_parent_id);
}

}  // namespace maidsafe
