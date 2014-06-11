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

#include "maidsafe/client.h"

#ifdef MAIDSAFE_BSD
extern "C" char **environ;
#endif

#include "maidsafe/common/process.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/routing/parameters.h"

#include "maidsafe/nfs/client/maid_node_nfs.h"

namespace maidsafe {

namespace test {

// Pre-condition : Need a Vault network running
TEST(ClientTest, FUNC_Constructor) {
  routing::Parameters::append_local_live_port_endpoint = true;
  routing::BootstrapContacts bootstrap_contacts;
  auto maid_and_signer(passport::CreateMaidAndSigner());
  {
    Client client_new_account(maid_and_signer, bootstrap_contacts);
  }
  LOG(kInfo) << "joining existing account";
  Client client_existing_account(maid_and_signer.first, bootstrap_contacts);
}

TEST(ClientTest, FUNC_RegisterVault) {
  routing::Parameters::append_local_live_port_endpoint = true;
  routing::BootstrapContacts bootstrap_contacts;
  auto maid_and_signer(passport::CreateMaidAndSigner());
  {
    Client client_new_account(maid_and_signer, bootstrap_contacts);
  }
  std::cout << "joining existing account" << std::endl;
  Client client_existing_account(maid_and_signer.first, bootstrap_contacts);
  passport::Anpmid anpmid;
  passport::Pmid pmid(anpmid);
  passport::PublicPmid public_pmid(pmid);
  // Put(public_pmid) should be done by VaultManager
  auto put_future = client_existing_account.pimpl_->Put(public_pmid);
  put_future.get();
  auto get_future = client_existing_account.pimpl_->Get(public_pmid.name());
  std::cout << " waiting to get pmid public key from network " << std::endl;
  get_future.get();
  std::cout << " RegisterVault " << std::endl;
  auto register_vault_future = client_existing_account.RegisterVault(pmid);
  register_vault_future.get();
}

}  // namespace test

}  // namespace maidsafe
