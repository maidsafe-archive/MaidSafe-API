/*  Copyright 2015 MaidSafe.net limited

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

#ifndef MAIDSAFE_DIRECTORY_INFO_H_
#define MAIDSAFE_DIRECTORY_INFO_H_

#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/drive/config.h"

namespace maidsafe {

struct DirectoryInfo {
  enum class AccessRights { kNone, kReadOnly, kReadWrite };

  DirectoryInfo() : path(), parent_id(), directory_id(), access_rights(AccessRights::kReadOnly) {}

  DirectoryInfo(const DirectoryInfo&) = default;

  DirectoryInfo(DirectoryInfo&& other)
      : path(std::move(other.path)),
        parent_id(std::move(other.parent_id)),
        directory_id(std::move(other.directory_id)),
        access_rights(std::move(other.access_rights)) {}

  DirectoryInfo& operator=(const DirectoryInfo&) = default;

  DirectoryInfo& operator=(DirectoryInfo&& other) {
    path = std::move(other.path);
    parent_id = std::move(other.parent_id);
    directory_id = std::move(other.directory_id);
    access_rights = std::move(other.access_rights);
    return *this;
  }

  DirectoryInfo(boost::filesystem::path path_in, drive::ParentId parent_id_in,
                drive::DirectoryId directory_id_in, AccessRights access_rights_in)
      : path(std::move(path_in)),
        parent_id(std::move(parent_id_in)),
        directory_id(std::move(directory_id_in)),
        access_rights(std::move(access_rights_in)) {}

  template <typename Archive>
  Archive& save(Archive& archive) const {
    return archive(path.string(), parent_id, directory_id, access_rights);
  }

  template <typename Archive>
  Archive& load(Archive& archive) {
    std::string path_as_string;
    archive(path_as_string, parent_id, directory_id, access_rights);
    path.assign(std::begin(path_as_string), std::end(path_as_string));
    return archive;
  }

  boost::filesystem::path path;
  drive::ParentId parent_id;
  drive::DirectoryId directory_id;
  AccessRights access_rights;
};

inline bool operator<(const DirectoryInfo& lhs, const DirectoryInfo& rhs) {
  return lhs.path < rhs.path;
}

}  // namespace maidsafe

#endif  // MAIDSAFE_DIRECTORY_INFO_H_
