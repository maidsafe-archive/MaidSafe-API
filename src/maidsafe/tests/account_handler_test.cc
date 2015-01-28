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

#include "maidsafe/detail/account_handler.h"

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/routing/parameters.h"

#include "maidsafe/detail/account.h"
#include "maidsafe/detail/account_getter.h"
#include "maidsafe/tests/test_utils.h"

namespace maidsafe {

namespace detail {

namespace test {

TEST(AccountHandlerTest, FUNC_Constructor) {
  LOG(kInfo) << "Account Handler for exisiting account";
  {
     AccountHandler{};
  }

  LOG(kInfo) << "Account Handler for new account";
  {
    auto maid_and_signer(passport::CreateMaidAndSigner());
    auto maid_client(nfs_client::MaidClient::MakeShared(maid_and_signer));
    Account account{ maid_and_signer };
    authentication::UserCredentials user_credentials{ GetRandomUserCredentials() };
    AccountHandler{ std::move(account), std::move(user_credentials), *maid_client };
  }
}

TEST(AccountHandlerTest, FUNC_EncryptDecryptAccount) {
  for (int i(0); i < 20; ++i) {
    Account account{ passport::CreateMaidAndSigner() };
    authentication::UserCredentials user_credentials{ GetRandomUserCredentials() };
    ImmutableData encrypted_account{ EncryptAccount(user_credentials, account) };
    Account decrypted_account{ encrypted_account, user_credentials };

    // TODO(Prkash) Check passport keys
    EXPECT_EQ(decrypted_account.passport->GetMaid().name(), account.passport->GetMaid().name());
    EXPECT_EQ(decrypted_account.timestamp, account.timestamp);
    EXPECT_EQ(decrypted_account.ip, account.ip);
    EXPECT_EQ(decrypted_account.port, account.port);
    EXPECT_EQ(decrypted_account.unique_user_id, account.unique_user_id);
    EXPECT_EQ(decrypted_account.root_parent_id, account.root_parent_id);
  }
}

TEST(AccountHandlerTest, FUNC_Login) {
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  auto maid_and_signer(passport::CreateMaidAndSigner());
  auto account_getter_future(AccountGetter::CreateAccountGetter());
  {
    LOG(kInfo) << "AccountHandlerTest -- Creating new account --";
    auto maid_client(nfs_client::MaidClient::MakeShared(maid_and_signer));
    Account account{ maid_and_signer };
    authentication::UserCredentials user_credentials{ MakeUserCredentials(user_credentials_tuple) };
    AccountHandler{ std::move(account), std::move(user_credentials), *maid_client };
  }
  try {
    LOG(kInfo) << "AccountHandlerTest -- Login for existing account --";
    AccountHandler account_handler{};
    LOG(kInfo) << "About to login.";
    authentication::UserCredentials user_credentials{ MakeUserCredentials(user_credentials_tuple) };
    std::shared_ptr<AccountGetter> account_getter{ account_getter_future.get() };
    account_handler.Login(std::move(user_credentials), *account_getter);
    LOG(kInfo) << "Login successful.";
    ASSERT_EQ(maid_and_signer.first.name(), account_handler.account().passport->GetMaid().name());
    auto maid_client(
        nfs_client::MaidClient::MakeShared(account_handler.account().passport->GetMaid()));
    LOG(kInfo) << "PrivateClient connection to account successful.";
  } catch (std::exception& e) {
    LOG(kError) << "Error on Login :" << boost::diagnostic_information(e);
    ASSERT_TRUE(false);
  }
}

TEST(AccountHandlerTest, FUNC_Save) {
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  auto maid_and_signer(passport::CreateMaidAndSigner());
  auto account_getter_future(AccountGetter::CreateAccountGetter());
  {
    LOG(kInfo) << "AccountHandlerTest -- Creating new account --";
    auto maid_client(nfs_client::MaidClient::MakeShared(maid_and_signer));
    Account account{ maid_and_signer };
    authentication::UserCredentials user_credentials{ MakeUserCredentials(user_credentials_tuple) };
    AccountHandler{ std::move(account), std::move(user_credentials), *maid_client };
  }
  try {
    LOG(kInfo) << "AccountHandlerTest -- Login for existing account --";
    AccountHandler account_handler{};
    LOG(kInfo) << "About to login.";
    authentication::UserCredentials user_credentials{ MakeUserCredentials(user_credentials_tuple) };
    std::shared_ptr<AccountGetter> account_getter{ account_getter_future.get() };
    account_handler.Login(std::move(user_credentials), *account_getter);
    LOG(kInfo) << "Login successful.";
    ASSERT_EQ(maid_and_signer.first.name(), account_handler.account().passport->GetMaid().name());
    auto maid_client(
        nfs_client::MaidClient::MakeShared(account_handler.account().passport->GetMaid()));
    LOG(kInfo) << "PrivateClient connection to account successful.";
    LOG(kInfo) << "AccountHandlerTest -- Saving account --";
    boost::posix_time::ptime timestamp{ account_handler.account().timestamp };
    for (int i(0); i != 10; ++i) {
      account_handler.Save(*maid_client);
      // TODO(Team) - check account fields are unchanged except 'timestamp'.
      EXPECT_NE(timestamp, account_handler.account().timestamp);
      account_handler.account().timestamp -= boost::posix_time::seconds{ 10 };
      timestamp = account_handler.account().timestamp;
      LOG(kInfo) << "Save account successful.";
    }
  } catch (std::exception& e) {
    GTEST_FAIL() << boost::diagnostic_information(e) << '\n';
  }
}

}  // namespace test

}  // namespace detail

}  // namespace maidsafe
