/*
arqinator: arq/types/commit.go
Implements an Arq Commit.

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
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/url"
	"regexp"
)

const (
	READ_IS_COMPRESSED        = true
	DO_NOT_READ_IS_COMPRESSED = false
)

var (
	LOCATION_REGEXP = regexp.MustCompile("^file://(?P<computer>[^/]+)(?P<path>.*)$")
)

type Commit struct {
	Header        *Header
	Author        *String
	Comment       *String
	ParentCommits []*BlobKey
	TreeBlobKey   *BlobKey

	Location *String
	// These fields aren't part of the file, but are derived fields of Location
	Computer string
	Path     string

	// only present for Commit v7 or older, never used
	MergeCommonAncestorSHA1 *String

	// only present for Commit v4 to v7
	IsMergeCommonAncestorEncryptionKeyStretched *Boolean

	CreationDate      *Date
	CommitFailedFiles []*CommitFailedFile

	// only present for Commit v8 or later
	HasMissingNodes *Boolean

	// only present for Commit v9 or later
	IsComplete *Boolean

	// a copy of the XML file as described in s3_data_format.txt
	ConfigPlistXML *Data
}

func (c Commit) String() string {
	return fmt.Sprintf("{Commit: Header=%s, Author=%s, Comment=%s, "+
		"ParentCommits=%s, TreeBlobKey=%s, Location=%s, "+
		"Computer=%s, Path=%s, MergeCommonAncestorSHA1=%s, "+
		"IsMergeCommonAncestorEncryptionKeyStretched=%s, "+
		"CreationDate=%s, CommitFailedFiles=%s, HasMissingNodes=%s, "+
		"IsComplete=%s}",
		c.Header, c.Author, c.Comment, c.ParentCommits, c.TreeBlobKey,
		c.Location, c.Computer, c.Path, c.MergeCommonAncestorSHA1,
		c.IsMergeCommonAncestorEncryptionKeyStretched, c.CreationDate,
		c.CommitFailedFiles, c.HasMissingNodes, c.IsComplete)
}

func ReadCommit(p *bytes.Buffer) (commit *Commit, err error) {
	var err2 error
	commit = &Commit{}
	if commit.Header, err = ReadHeader(p); err != nil {
		err = errors.New(fmt.Sprintf("ReadCommit header couldn't be parsed: %s", err))
		return
	}
	if commit.Author, err = ReadString(p); err != nil {
		err = errors.New(fmt.Sprintf("ReadCommit failed during Author parsing: %s", err))
		return
	}
	if commit.Comment, err = ReadString(p); err != nil {
		err = errors.New(fmt.Sprintf("ReadCommit failed during Comment parsing: %s", err))
		return
	}
	var i, numParentCommits uint64
	binary.Read(p, binary.BigEndian, &numParentCommits)
	commit.ParentCommits = make([]*BlobKey, 0)
	for i = 0; i < numParentCommits; i++ {
		var parentCommit *BlobKey
		parentCommit, err = ReadBlobKey(p, commit.Header, DO_NOT_READ_IS_COMPRESSED)
		if err != nil {
			log.Debugf("Failed to ReadBlobKey for commit %s: %s", commit, err)
			return
		}
		commit.ParentCommits = append(commit.ParentCommits, parentCommit)
	}
	commit.TreeBlobKey, err = ReadBlobKey(p, commit.Header, READ_IS_COMPRESSED)
	if err != nil {
		log.Debugf("ReadCommit failed to read TreeBlobKey %s", err)
		return
	}
	log.Debugf("TREE BLOB KEY = %s", commit.TreeBlobKey)

	if commit.Location, err2 = ReadString(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadCommit failed during Location parsing: %s", err2))
		log.Debugf("%s", err)
		return
	}
	//log.Debug(commit.Location)
	unescapedLocation, err := url.QueryUnescape(commit.Location.ToString())
	if err == nil {
		log.Debugf("Successfully URL unescaped location %s, use it instead.", commit.Location)
		commit.Location = NewString(unescapedLocation)
	}

	locationMatcher := LOCATION_REGEXP.FindAllSubmatch(commit.Location.Data, -1)
	if locationMatcher == nil {
		err = errors.New(fmt.Sprintf("Failed to parse commit.Location %s using LOCATION_REGEXP.", commit.Location))
		log.Debugf("%s", err)
		return
	}
	commit.Computer = string(locationMatcher[0][1])
	commit.Path = string(locationMatcher[0][2])

	if commit.Header.Version < 8 {
		if commit.MergeCommonAncestorSHA1, err2 = ReadString(p); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadCommit failed during MergeCommonAncestorSHA1 parsing: %s", err2))
			log.Debugf("%s", err)
			return
		}
		if commit.Header.Version >= 4 {
			if commit.IsMergeCommonAncestorEncryptionKeyStretched, err2 = ReadBoolean(p); err2 != nil {
				err = errors.New(fmt.Sprintf("ReadBlobKey failed during IsMergeCommonAncestorEncryptionKeyStretched parsing: %s", err2))
				return
			}
		}
	}
	if commit.CreationDate, err = ReadDate(p); err != nil {
		log.Debugf("ReadCommit failed to read CreationDate %s", err)
		return
	}
	if commit.Header.Version >= 3 {
		var i, numFailedFiles uint64
		binary.Read(p, binary.BigEndian, &numFailedFiles)
		commit.CommitFailedFiles = make([]*CommitFailedFile, 0)
		for i = 0; i < numFailedFiles; i++ {
			var commitFailedFile *CommitFailedFile
			commitFailedFile, err = ReadCommitFailedFile(p)
			if err != nil {
				log.Debugf("Failed to ReadCommitFailedFile for commit %s: %s", commit, err)
				return
			}
			commit.CommitFailedFiles = append(commit.CommitFailedFiles,
				commitFailedFile)
		}
	}
	if commit.Header.Version >= 8 {
		if commit.HasMissingNodes, err2 = ReadBoolean(p); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadCommit failed during HasMissingNodes parsing: %s", err2))
			log.Debugf("%s", err)
			return
		}
	}
	if commit.Header.Version >= 9 {
		if commit.IsComplete, err2 = ReadBoolean(p); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadCommit failed during IsComplete parsing: %s", err2))
			log.Debugf("%s", err)
			return
		}
	}
	if commit.Header.Version >= 5 {
		if commit.ConfigPlistXML, err2 = ReadData(p); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadCommit failed during ConfigPlistXML parsing: %s", err2))
			log.Debugf("%s", err)
			return
		}
	}
	return
}
