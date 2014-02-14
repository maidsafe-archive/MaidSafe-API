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

#ifndef MAIDSAFE_DETAIL_CLIENT_IMPL_H_
#define MAIDSAFE_DETAIL_CLIENT_IMPL_H_


#include "maidsafe/client.h"

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/client/data_getter.h"
#include "maidsafe/nfs/client/maid_node_nfs.h"


namespace maidsafe {

namespace detail {

class ClientImpl {

 public:

  ClientImpl();

  void SaveSession();  // NO THROW

  Client::ImmutableDataFuture Get(const ImmutableData::Name& immutable_data_name,
                                  const std::chrono::steady_clock::duration& timeout);

  Client::PutFuture Put(const ImmutableData& immutable_data,
                        const std::chrono::steady_clock::duration& timeout);

  void Delete(const ImmutableData::Name& immutable_data_name);

  Client::VersionNamesFuture GetVersions(const MutableData::Name& mutable_data_name,
                                         const std::chrono::steady_clock::duration& timeout);

  Client::VersionNamesFuture GetBranch(const MutableData::Name& mutable_data_name,
                                       const StructuredDataVersions::VersionName& branch_tip,
                                       const std::chrono::steady_clock::duration& timeout);

  Client::PutFuture PutVersion(const MutableData::Name& mutable_data_name,
                               const StructuredDataVersions::VersionName& old_version_name,
                               const StructuredDataVersions::VersionName& new_version_name);

  void DeleteBranchUntilFork(const MutableData::Name& mutable_data_name,
                             const StructuredDataVersions::VersionName& branch_tip);

 private:
  AsioService asio_service_;
  std::unique_ptr<routing::Routing> routing_;
  std::unique_ptr<nfs_client::DataGetter> data_getter_;
  std::unique_ptr<nfs_client::MaidNodeNfs> maid_node_nfs_;
};

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DETAIL_CLIENT_IMPL_H_
