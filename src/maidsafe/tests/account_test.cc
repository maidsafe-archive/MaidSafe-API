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

#include "maidsafe/detail/account.h"

#include <memory>

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/tests/test_utils.h"

namespace maidsafe {

namespace detail {

namespace test {

// Tests default constructor, which is intended to be used when creating a new account.
TEST(AccountTest, BEH_Create) {
  std::unique_ptr<Account> account;
  authentication::UserCredentials user_credentials{ GetRandomUserCredentials() };
  // construct Account
  EXPECT_NO_THROW(account = maidsafe::make_unique<Account>(passport::CreateMaidAndSigner()));

  // Check account contents have been initialised as expected
  EXPECT_NO_THROW(account->passport->Encrypt(user_credentials));
  EXPECT_EQ(boost::posix_time::ptime(boost::date_time::not_a_date_time), account->timestamp);
  EXPECT_TRUE(account->ip.is_unspecified());
  EXPECT_EQ(0, account->port);
  EXPECT_FALSE(account->unique_user_id.IsInitialised());
  EXPECT_FALSE(account->root_parent_id.IsInitialised());
}

// Tests serialising/encrypting functions and decrypting/parsing constructor.
TEST(AccountTest, FUNC_SaveAndLogin) {
  Account account0{ passport::CreateMaidAndSigner() };
  std::unique_ptr<ImmutableData> encrypted_account0;
  authentication::UserCredentials user_credentials{ GetRandomUserCredentials() };

  // Check we can handle serialising a default-contructed account.
  EXPECT_NO_THROW(encrypted_account0 =
      maidsafe::make_unique<ImmutableData>(EncryptAccount(user_credentials, account0)));
  EXPECT_NE(boost::posix_time::ptime(boost::date_time::not_a_date_time), account0.timestamp);

  // Parse default-constructed account and update it.
  std::unique_ptr<Account> account1;
  EXPECT_NO_THROW(account1 = maidsafe::make_unique<Account>(*encrypted_account0, user_credentials));
  EXPECT_EQ(account0.passport->Encrypt(user_credentials),
            account1->passport->Encrypt(user_credentials));
  EXPECT_EQ(account0.timestamp, account1->timestamp);
  account0.timestamp -= boost::posix_time::seconds{ 10 };  // Pretend this was saved 10 seconds ago
  EXPECT_EQ(account0.ip, account1->ip);
  EXPECT_EQ(account0.port, account1->port);
  EXPECT_EQ(account0.unique_user_id, account1->unique_user_id);
  EXPECT_EQ(account0.root_parent_id, account1->root_parent_id);

  const boost::asio::ip::address ip(boost::asio::ip::address::from_string("123.124.125.126"));
  const uint16_t port(static_cast<uint16_t>(RandomUint32()));
  const Identity unique_user_id(RandomString(64));
  const Identity root_parent_id(RandomString(64));
  account1->ip = ip;
  account1->port = port;
  account1->unique_user_id = unique_user_id;
  account1->root_parent_id = root_parent_id;

  // Encrypt updated account, then parse and check.
  std::unique_ptr<ImmutableData> encrypted_account1;
  EXPECT_NO_THROW(encrypted_account1 =
      maidsafe::make_unique<ImmutableData>(EncryptAccount(user_credentials, *account1)));
  EXPECT_LT(account0.timestamp, account1->timestamp);
  EXPECT_EQ(account1->ip, ip);
  EXPECT_EQ(account1->port, port);
  EXPECT_EQ(account1->unique_user_id, unique_user_id);
  EXPECT_EQ(account1->root_parent_id, root_parent_id);

  std::unique_ptr<Account> account2;
  EXPECT_NO_THROW(account2 = maidsafe::make_unique<Account>(*encrypted_account1, user_credentials));
  EXPECT_EQ(account1->passport->Encrypt(user_credentials),
            account2->passport->Encrypt(user_credentials));
  EXPECT_EQ(account1->timestamp, account2->timestamp);
  EXPECT_EQ(account1->ip, account2->ip);
  EXPECT_EQ(account1->port, account2->port);
  EXPECT_EQ(account1->unique_user_id, account2->unique_user_id);
  EXPECT_EQ(account1->root_parent_id, account2->root_parent_id);
}

TEST(AccountTest, FUNC_MoveConstructAndAssign) {
  Account initial_account{ passport::CreateMaidAndSigner() };
  authentication::UserCredentials user_credentials{ GetRandomUserCredentials() };
  initial_account.timestamp = boost::posix_time::second_clock::universal_time();
  const crypto::CipherText encrypted_passport{
      initial_account.passport->Encrypt(user_credentials) };
  const boost::posix_time::ptime timestamp{ initial_account.timestamp };
  const boost::asio::ip::address ip{ boost::asio::ip::address::from_string("234.235.236.237") };
  const uint16_t port{ static_cast<uint16_t>(RandomUint32()) };
  const Identity unique_user_id{ RandomString(64) };
  const Identity root_parent_id{ RandomString(64) };
  initial_account.ip = ip;
  initial_account.port = port;
  initial_account.unique_user_id = unique_user_id;
  initial_account.root_parent_id = root_parent_id;

  Account moved_to_account{ std::move(initial_account) };
  EXPECT_EQ(encrypted_passport, moved_to_account.passport->Encrypt(user_credentials));
  EXPECT_EQ(timestamp, moved_to_account.timestamp);
  EXPECT_EQ(ip, moved_to_account.ip);
  EXPECT_EQ(port, moved_to_account.port);
  EXPECT_EQ(unique_user_id, moved_to_account.unique_user_id);
  EXPECT_EQ(root_parent_id, moved_to_account.root_parent_id);

  Account assigned_to_account{ passport::CreateMaidAndSigner() };
  assigned_to_account = std::move(moved_to_account);
  EXPECT_EQ(encrypted_passport, assigned_to_account.passport->Encrypt(user_credentials));
  EXPECT_EQ(timestamp, assigned_to_account.timestamp);
  EXPECT_EQ(ip, assigned_to_account.ip);
  EXPECT_EQ(port, assigned_to_account.port);
  EXPECT_EQ(unique_user_id, assigned_to_account.unique_user_id);
  EXPECT_EQ(root_parent_id, assigned_to_account.root_parent_id);
}

}  // namespace test

}  // namespace detail

}  // namespace maidsafe
