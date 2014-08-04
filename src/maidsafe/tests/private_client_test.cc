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

#include "maidsafe/private_client.h"

#ifdef MAIDSAFE_BSD
extern "C" char **environ;
#endif

#include "maidsafe/common/test.h"
#include "maidsafe/routing/parameters.h"

#include "maidsafe/detail/account.h"
#include "maidsafe/detail/account_getter.h"
#include "maidsafe/tests/test_utils.h"

namespace maidsafe {

namespace test {

TEST(PrivateClientTest, FUNC_CreateAccount) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  std::future<PrivateClient> private_client_future{
      PrivateClient::CreateAccount(std::get<0>(user_credentials_tuple),
          std::get<1>(user_credentials_tuple), std::get<2>(user_credentials_tuple)) };
  PrivateClient private_client{ private_client_future.get() };
  private_client.Logout();
}

TEST(PrivateClientTest, FUNC_CreateAccountMultiple) {
  const int kCount{ 10 };
  routing::Parameters::append_local_live_port_endpoint = true;
  for (int i(0); i != kCount; ++i) {
    auto user_credentials_tuple(GetRandomUserCredentialsTuple());
    PrivateClient::CreateAccount(std::get<0>(user_credentials_tuple),
                                 std::get<1>(user_credentials_tuple),
                                 std::get<2>(user_credentials_tuple)).get().Logout();
  }
}

TEST(PrivateClientTest, FUNC_Login) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  PrivateClient private_client{ PrivateClient::CreateAccount(std::get<0>(user_credentials_tuple),
      std::get<1>(user_credentials_tuple), std::get<2>(user_credentials_tuple)).get() };
  private_client.Logout();
  private_client = PrivateClient::Login(std::get<0>(user_credentials_tuple),
      std::get<1>(user_credentials_tuple), std::get<2>(user_credentials_tuple)).get();
}

TEST(PrivateClientTest, FUNC_SaveAccount) {
  const int kCount{ 10 };
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  PrivateClient private_client{ PrivateClient::CreateAccount(std::get<0>(user_credentials_tuple),
      std::get<1>(user_credentials_tuple), std::get<2>(user_credentials_tuple)).get() };
  for (int i(0); i != kCount; ++i) {
    private_client.SaveAccount();
    LOG(kInfo) << "Save account successful.";
  }
  private_client.Logout();
}

// TODO(Team)  move to nfs
// TEST(ClientTest, FUNC_Constructor) {
//  routing::Parameters::append_local_live_port_endpoint = true;
//  routing::BootstrapContacts bootstrap_contacts;
//  auto maid_and_signer(passport::CreateMaidAndSigner());
//  {
//    auto nfs_new_account =
//        nfs_client::MaidNodeNfs::MakeShared(maid_and_signer, bootstrap_contacts);
//  }
//  LOG(kInfo) << "joining existing account";
//  auto nfs_existing_account = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer.first,
//                                                                  bootstrap_contacts);
// }

// TEST(ClientTest, FUNC_RegisterVault) {
//  routing::Parameters::append_local_live_port_endpoint = true;
//  routing::BootstrapContacts bootstrap_contacts;
//  auto maid_and_signer(passport::CreateMaidAndSigner());
//  {
//    auto nfs_new_account = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer,
//                           bootstrap_contacts);
//  }
//  std::cout << "joining existing account" << std::endl;
//  auto nfs_existing_account = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer.first,
//                                                                  bootstrap_contacts);
//  passport::Anpmid anpmid;
//  passport::Pmid pmid(anpmid);
//  passport::PublicPmid public_pmid(pmid);
//  // Put(public_pmid) should be done by VaultManager
//  auto put_future = nfs_existing_account->Put(public_pmid);
//  put_future.get();
//  auto get_future = nfs_existing_account->Get(public_pmid.name());
//  std::cout << " waiting to get pmid public key from network " << std::endl;
//  get_future.get();
//  std::cout << " RegisterVault " << std::endl;
//  auto register_vault_future = nfs_existing_account->RegisterPmid(pmid);
//  register_vault_future.get();
// }

}  // namespace test

}  // namespace maidsafe
