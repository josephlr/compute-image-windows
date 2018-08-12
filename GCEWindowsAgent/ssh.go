//  Copyright 2018 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/compute-image-windows/logger"
)

const (
	authorizedKeysFileHeader = "# Added by Google Compute Engine\n"
	googleSSHSubDirectory    = "google_compute_authorized_keys"
	directoryPermissions     = 0700
	filePermissions          = 0600
)

var filesystemState userState

func blockProjectSSHKeys(metadata *metadataJSON) bool {
	return strings.ToLower(metadata.Instance.Attributes.BlockProjectSSHKeys) == "true"
}

func authorizedKeysDir() (string, error) {
	sshDir, err := sshDataDir()
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(sshDir); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	} else if !st.IsDir() {
		return "", fmt.Errorf("not a directory: %v", sshDir)
	}
	return filepath.Join(sshDir, googleSSHSubDirectory), nil
}

func timeHasExpired(expireTime time.Time) bool {
	return !expireTime.IsZero() && expireTime.Before(time.Now())
}

func minTime(t1 time.Time, t2 time.Time) time.Time {
	if t1.IsZero() {
		return t2
	}
	if t2.IsZero() || t1.Before(t2) {
		return t1
	}
	return t2
}

type userData struct {
	keys               []string
	earliestExpireTime time.Time
}

type userMapping = map[string]userData

func desiredKeyMapping() userMapping {
	um := userMapping{}
	addKeysFromMetadata(um, newMetadata.Instance.Attributes)
	if !blockProjectSSHKeys(newMetadata) {
		addKeysFromMetadata(um, newMetadata.Project.Attributes)
	}
	return um
}

func addKeysFromMetadata(um userMapping, attributes attributesJSON) {
	for _, line := range strings.Split(attributes.SSHKeys, "\n") {
		splitLine := strings.SplitAfterN(line, ":", 2)
		if len(splitLine) != 2 {
			// TODO: bad key format
			continue
		}

		username := splitLine[0]
		key := splitLine[1]
		expireTime := keyExpireTime(key)
		if timeHasExpired(expireTime) {
			// TODO: key expired
			continue
		}

		userData := um[username]
		userData.keys = append(userData.keys, key)
		userData.earliestExpireTime = minTime(userData.earliestExpireTime, expireTime)
		um[username] = userData
	}
}

// Uses Google-specific semantics of the OpenSSH public key format's comment
// field to determine if an SSH key is past its expiration timestamp, and
// therefore no longer to be trusted. This format is still subject to change.
// Reliance on it in any way is at your own risk.
func keyExpireTime(key string) time.Time {
	splitKey := strings.SplitAfterN(key, " ", 4)
	if len(splitKey) != 4 {
		// TODO: no json
		return time.Time{}
	}
	schema := splitKey[2]
	jsonData := []byte(splitKey[3])

	if schema != "google-ssh" {
		// TODO: Inval schema
		return time.Time{}
	}

	data := struct {
		userName string
		expireOn string
	}{}
	if json.Unmarshal(jsonData, &data) != nil {
		// TODO: Inval JSON
		return time.Time{}
	}

	expireTime, err := time.Parse("2006-01-02T15:04:05+0000", data.expireOn)
	if err != nil {
		// TODO: Bad Date
		return time.Time{}
	}
	return expireTime
}

type userState struct {
	authorizedKeysDir  string
	mapping            userMapping
	earliestExpireTime time.Time
}

func (us *userState) setupGoogleDirectory() error {
	err := os.Mkdir(us.authorizedKeysDir, directoryPermissions)
	if err == nil || os.IsExist(err) {
		return nil
	}
	return err
}

func (us *userState) usernamesToUpdate(desired userMapping) []string {
	toUpdate := []string{}
	for username, data := range desired {
		if !reflect.DeepEqual(data, us.mapping[username]) {
			toUpdate = append(toUpdate, username)
		}
	}
	for username := range us.mapping {
		if len(desired[username].keys) == 0 {
			toUpdate = append(toUpdate, username)
		}
	}
	return toUpdate
}

func (us *userState) updateUserData(username string, data userData) error {
	filePath := filepath.Join(us.authorizedKeysDir, username)
	if len(data.keys) == 0 {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		delete(us.mapping, username)
		return nil
	}

	// Our file should have a comment indicating it's managed by Compute Engine.
	contents := bytes.NewBuffer(nil)
	contents.WriteString(authorizedKeysFileHeader)
	for _, key := range data.keys {
		contents.WriteString(key)
		contents.WriteByte('\n')
	}
	if err := ioutil.WriteFile(filePath, contents.Bytes(), filePermissions); err != nil {
		return err
	}
	us.mapping[username] = data
	return fixAuthorizedKeysFilePermissions(filePath)
}

func (us *userState) updateExpireTime() {
	us.earliestExpireTime = time.Time{}
	for _, data := range us.mapping {
		us.earliestExpireTime = minTime(us.earliestExpireTime, data.earliestExpireTime)
	}
}

type sshMgr struct{}

func (m *sshMgr) diff() bool {
	return blockProjectSSHKeys(oldMetadata) != blockProjectSSHKeys(newMetadata) ||
		oldMetadata.Instance.Attributes.SSHKeys != newMetadata.Instance.Attributes.SSHKeys ||
		oldMetadata.Project.Attributes.SSHKeys != newMetadata.Project.Attributes.SSHKeys
}

func (m *sshMgr) timeout() bool {
	return timeHasExpired(filesystemState.earliestExpireTime)
}

func (m *sshMgr) disabled() bool {
	keysDir, err := authorizedKeysDir()
	if err != nil {
		logger.Error(err)
		return true
	}
	if keysDir == "" {
		logger.Info("OpenSSH is not installed")
		filesystemState = userState{}
		return true
	}
	if keysDir != filesystemState.authorizedKeysDir {
		logger.Info("OpenSSH now installed at %v", keysDir)
		filesystemState.authorizedKeysDir = keysDir
		filesystemState.mapping = userMapping{}
		filesystemState.earliestExpireTime = time.Time{}
	}
	return false
}

func (m *sshMgr) set() error {
	desired := desiredKeyMapping()
	toUpdate := filesystemState.usernamesToUpdate(desired)
	if len(toUpdate) == 0 {
		logger.Info("No users need to have their authorized keys updated")
		return nil
	}
	filesystemState.setupGoogleDirectory()

	updateError := false
	for _, username := range toUpdate {
		data := desired[username]
		if err := filesystemState.updateUserData(username, data); err != nil {
			// TODO: Log error
			updateError = true
		}
	}
	filesystemState.updateExpireTime()

	if updateError {
		// TODO: Return some general error
		return nil
	}
	return nil
}
