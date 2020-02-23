/*
arqinator: arq/types/blob_key.go
Implements an Arq BlobKey.

Copyright 2015 Asim Ihsan

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package arq_types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
)

const (
	STORAGE_TYPE_S3      = uint32(1)
	STORAGE_TYPE_GLACIER = uint32(2)
)

func (b BlobKey) String() string {
	if b.Header.Type == BLOB_TYPE_COMMIT {
		return fmt.Sprintf("{BlobKey: Header=%s, SHA1=%s, "+
			"IsEncryptionKeyStretched=%s, CompType=%s}",
			b.Header, hex.EncodeToString(b.SHA1[:]), b.IsEncryptionKeyStretched,
			b.CompressionType)
	} else {
		return fmt.Sprintf("{BlobKey: Header=%s, SHA1=%s, "+
			"IsEncryptionKeyStretched=%s, StorageType=%d, ArchiveId=%s, "+
			"ArchiveSize=%d, ArchiveUploadedDate=%s}",
			b.Header, hex.EncodeToString(b.SHA1[:]), b.IsEncryptionKeyStretched,
			b.StorageType, b.ArchiveId, b.ArchiveSize, b.ArchiveUploadedDate)
	}
}

type BlobKey struct {
	Header *Header
	SHA1   *[20]byte

	// only present for Tree v14 or later or Commit v4 or later
	// applies for both trees and commits
	IsEncryptionKeyStretched *Boolean

	// only present for Commit v8 or later
	// only for a Tree BlobKey, not for ParentCommit BlobKey
	CompressionType *CompressionType

	// only for tree v17 or later
	StorageType         uint32
	ArchiveId           *String
	ArchiveSize         uint64
	ArchiveUploadedDate *Date
}

func ReadBlobKey(p *bytes.Buffer, h *Header, readIsCompressed bool) (blobKey *BlobKey, err error) {
	var (
		err2 error
	)

	blobKey = &BlobKey{Header: h}
	if blobKey.SHA1, err2 = ReadStringAsSHA1(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadBlobKey failed to hex decode hex: %s", err2))
		log.Debugf("%s", err)
		return
	}
	if (h.Type == BLOB_TYPE_TREE && h.Version >= 14) ||
		(h.Type == BLOB_TYPE_COMMIT && h.Version >= 4) {
		if blobKey.IsEncryptionKeyStretched, err2 = ReadBoolean(p); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadBlobKey failed during IsEncryptionKeyStretched parsing: %s", err2))
			return
		}
	}
	if h.Type == BLOB_TYPE_COMMIT && h.Version >= 8 && readIsCompressed {
		blobKey.CompressionType, err2 = ReadCompressionType(p, h.Version >= 10)
		if err2 != nil {
			err = errors.New(fmt.Sprintf("ReadBlobKey failed during IsCompressed parsing: %s", err2))
			return
		}
	}
	if h.Type == BLOB_TYPE_TREE && h.Version >= 17 {
		binary.Read(p, binary.BigEndian, &blobKey.StorageType)

		if blobKey.ArchiveId, err = ReadString(p); err != nil {
			log.Debugf("ReadBlobKey failed to read ArchiveId %s", err)
			return
		}
		binary.Read(p, binary.BigEndian, &blobKey.ArchiveSize)
		if blobKey.ArchiveUploadedDate, err = ReadDate(p); err != nil {
			log.Debugf("ReadBlobKey failed to read ArchiveUploadedDate %s", err)
			return
		}
	}
	return
}
