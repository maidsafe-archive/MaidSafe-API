/*  Copyright 2013 MaidSafe.net limited

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

#include <chrono>
#include <memory>

#include "boost/signals2/signal.hpp"
#include "boost/thread/future.hpp"

#include "maidsafe/data_types/immutable_data.h"
#include "maidsafe/data_types/mutable_data.h"
#include "maidsafe/data_types/structured_data_versions.h"

#ifndef MAIDSAFE_CLIENT_H_
#define MAIDSAFE_CLIENT_H_

namespace maidsafe {

class Client {
 public:

  typedef boost::future<ImmutableData> ImmutableDataFuture;
  typedef boost::future<void> PutFuture;
  typedef boost::future<std::vector<StructuredDataVersions::VersionName>> VersionNamesFuture;

  ~Client(); // Should call SaveSession

  void SaveSession();  // NO THROW

  // immutable data
  ImmutableDataFuture Get(const ImmutableData::Name& immutable_data_name,
    const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  PutFuture Put(const ImmutableData& immutable_data,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  void Delete(const ImmutableData::Name& immutable_data_name);


  // structured data
  VersionNamesFuture GetVersions(const MutableData::Name& mutable_data_name,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  VersionNamesFuture GetBranch(const MutableData::Name& mutable_data_name,
                               const StructuredDataVersions::VersionName& branch_tip,
                               const std::chrono::steady_clock::duration& timeout =
                                   std::chrono::seconds(10));

  // FIXME
  template <typename DataName>
  PutFuture PutVersion(const DataName& data_name,
                  const StructuredDataVersions::VersionName& old_version_name,
                  const StructuredDataVersions::VersionName& new_version_name);
  // FIXME
  template <typename DataName>
  void DeleteBranchUntilFork(const DataName& data_name,
                             const StructuredDataVersions::VersionName& branch_tip);

};

}  // namespace maidsafe

#endif // MAIDSAFE_CLIENT_H_

