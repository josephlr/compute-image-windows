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
	"path/filepath"

	"golang.org/x/sys/windows"
)

var FOLDERID_ProgramData = windows.GUID{0x62AB5D82, 0xFDC1, 0x4DC3, [8]byte{0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97}}

func sshDataDir() (string, error) {
	programData, err := windows.SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(programData, "ssh"), nil
}

func fixAuthorizedKeysFilePermissions(path string) error {
	// TODO implement
	return nil
}
