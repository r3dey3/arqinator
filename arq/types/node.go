/*
arqinator: arq/types/node.go
Implements an Arq Node.

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
	"github.com/dustin/go-humanize"
	log "github.com/sirupsen/logrus"
	"os"
	"text/tabwriter"
	"time"
)

type Node struct {
	Name                     *String
	TreeVersion              int
	IsTree                   *Boolean
	TreeContainsMissingItems *Boolean
	DataCompressionType      *CompressionType
	XattrsCompressionType    *CompressionType
	AclCompressionType       *CompressionType
	DataBlobKeys             []*BlobKey
	UncompressedDataSize     uint64
	ThumbnailBlobKey         *BlobKey
	PreviewBlobKey           *BlobKey
	XattrsBlobKey            *BlobKey
	XattrsSize               uint64
	AclBlobKey               *BlobKey
	Uid                      int32
	Gid                      int32
	Mode                     os.FileMode
	MtimeSec                 int64
	MtimeNsec                int64
	Flags                    int64
	FinderFlags              int32
	ExtendedFinderFlags      int32
	FinderFileType           *String
	FinderFileCreator        *String
	FileExtensionHidden      *Boolean
	StDev                    int32
	StIno                    int32
	StNlink                  uint32
	StRdev                   int32
	CtimeSec                 int64
	CtimeNsec                int64
	CreateTimeSec            int64
	CreateTimeNsec           int64
	StBlocks                 int64
	StBlksize                uint32
}

func (n Node) String() string {
	return fmt.Sprintf("{Node: Name=%s, TreeVersion=%d, IsTree=%s, "+
		"TreeContainsMissingItems=%s, DataCompressionType=%s, "+
		"XattrsCompressionType=%s, AclCompressionType=%s, len(DataBlobKeys)=%d, "+
		"UncompressedDataSize=%d, XattrsBlobKey=%s, XattrsSize=%d, "+
		"AclBlobKey=%s, Uid=%d, Gid=%d, Mode=%s, MtimeSec=%d, MtimeNsec=%d, "+
		"Flags=%d, FinderFlags=%d, ExtendedFinderFlags=%d, FinderFileType=%s, "+
		"FinderFileCreator=%s, FileExtensionHidden=%s, StDev=%d, StIno=%d, "+
		"StNlink=%d, StRdev=%d, CtimeSec=%d, CtimeNsec=%d, CreateTimeSec=%d, "+
		"CreateTimeNsec=%d, StBlocks=%d, StBlkSize=%d}",
		n.Name, n.TreeVersion, n.IsTree, n.TreeContainsMissingItems,
		n.DataCompressionType, n.XattrsCompressionType, n.AclCompressionType,
		len(n.DataBlobKeys), n.UncompressedDataSize, n.XattrsBlobKey,
		n.XattrsSize, n.AclBlobKey, n.Uid, n.Gid, n.Mode, n.MtimeSec,
		n.MtimeNsec, n.Flags, n.FinderFlags, n.ExtendedFinderFlags,
		n.FinderFileType, n.FinderFileCreator, n.FileExtensionHidden, n.StDev,
		n.StIno, n.StNlink, n.StRdev, n.CtimeSec, n.CtimeNsec, n.CreateTimeSec,
		n.CreateTimeNsec, n.StBlocks, n.StBlksize)
}

func getListOutputWriter() *tabwriter.Writer {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	return w
}

func (n *Node) PrintOutput() {
	w := getListOutputWriter()
	modifiedTime := fmt.Sprintf("%s", time.Unix(n.MtimeSec, n.MtimeNsec))
	size := humanize.Bytes(n.UncompressedDataSize)
	mode := fmt.Sprintf("%s", n.Mode)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", mode, modifiedTime, size, n.Name)
	w.Flush()
}

func ReadNodes(p *bytes.Buffer, treeHeader *Header) (nodes []*Node, err error) {
	var i, numNodes uint32
	binary.Read(p, binary.BigEndian, &numNodes)
	if numNodes > 10000 {
		return nil, errors.New("Too many nodes")
	}
	nodes = make([]*Node, numNodes)
	log.Debugf("Attempting to read %d nodes", numNodes)
	for i = 0; i < numNodes; i++ {
		var node *Node
		node, err = ReadNode(p, treeHeader)
		if err != nil {
			log.Debugf("ReadNode failed to read node: %s", err)
			return
		}
		nodes[i] = node
	}
	return
}

func ReadNode(p *bytes.Buffer, treeHeader *Header) (node *Node, err error) {
	var err2 error
	node = &Node{TreeVersion: treeHeader.Version}
	if node.Name, err2 = ReadString(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadNode failed during Name parsing: %s", err2))
		return
	}

	if node.IsTree, err2 = ReadBoolean(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadNode failed during IsTree parsing: %s", err2))
		return
	}

	if node.TreeVersion >= 18 {
		if node.TreeContainsMissingItems, err2 = ReadBoolean(p); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadNode failed during TreeContainsMissingItems parsing: %s", err2))
			return
		}
	}

	if node.TreeVersion >= 12 {
		new_type := node.TreeVersion >= 19
		if node.DataCompressionType, err2 = ReadCompressionType(p, new_type); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadNode failed during DataAreCompressed parsing: %s", err2))
			return
		}
		if node.XattrsCompressionType, err2 = ReadCompressionType(p, new_type); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadNode failed during XattrsAreCompressed parsing: %s", err2))
			return
		}
		if node.AclCompressionType, err2 = ReadCompressionType(p, new_type); err2 != nil {
			err = errors.New(fmt.Sprintf("ReadNode failed during AclIsCompressed parsing: %s", err2))
			return
		}
	}
	log.Debug(node)
	var i, numDataBlobKeys uint32
	binary.Read(p, binary.BigEndian, &numDataBlobKeys)
	node.DataBlobKeys = make([]*BlobKey, numDataBlobKeys)
	for i = 0; i < numDataBlobKeys; i++ {
		var dataBlobKey *BlobKey
		dataBlobKey, err = ReadBlobKey(p, treeHeader, node.DataCompressionType.Type == 1)
		if err != nil {
			log.Debugf("ReadNode failed to read dataBlobKey: %s", err)
			return
		}
		node.DataBlobKeys[i] = dataBlobKey
	}
	binary.Read(p, binary.BigEndian, &node.UncompressedDataSize)
	if node.TreeVersion < 18 {
		if node.ThumbnailBlobKey, err = ReadBlobKey(p, treeHeader, false); err != nil {
			err = errors.New(fmt.Sprintf("ReadNode failed during ThumbnailBlobKey parsing: %s", err2))
			return
		}
		if node.PreviewBlobKey, err = ReadBlobKey(p, treeHeader, false); err != nil {
			err = errors.New(fmt.Sprintf("ReadNode failed during PreviewBlobKey parsing: %s", err2))
			return
		}
	}
	if node.XattrsBlobKey, err = ReadBlobKey(p, treeHeader, true); err != nil {
		err = errors.New(fmt.Sprintf("ReadNode XattrsBlobKey couldn't be parsed: %s", err))
		return
	}
	if node.XattrsBlobKey.SHA1 == nil {
		node.XattrsBlobKey = nil
	}
	binary.Read(p, binary.BigEndian, &node.XattrsSize)
	if node.AclBlobKey, err = ReadBlobKey(p, treeHeader, true); err != nil {
		err = errors.New(fmt.Sprintf("ReadNode AclBlobKey couldn't be parsed: %s", err))
		return
	}
	if node.AclBlobKey.SHA1 == nil {
		node.AclBlobKey = nil
	}
	binary.Read(p, binary.BigEndian, &node.Uid)
	binary.Read(p, binary.BigEndian, &node.Gid)
	binary.Read(p, binary.BigEndian, &node.Mode)
	binary.Read(p, binary.BigEndian, &node.MtimeSec)
	binary.Read(p, binary.BigEndian, &node.MtimeNsec)
	binary.Read(p, binary.BigEndian, &node.Flags)
	binary.Read(p, binary.BigEndian, &node.FinderFlags)
	binary.Read(p, binary.BigEndian, &node.ExtendedFinderFlags)
	if node.FinderFileType, err2 = ReadString(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadNode failed during FinderFileType parsing: %s", err2))
		return
	}
	if node.FinderFileCreator, err2 = ReadString(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadNode failed during FinderFileCreator parsing: %s", err2))
		return
	}
	if node.FileExtensionHidden, err2 = ReadBoolean(p); err2 != nil {
		err = errors.New(fmt.Sprintf("ReadNode failed during FileExtensionHidden parsing: %s", err2))
		return
	}
	binary.Read(p, binary.BigEndian, &node.StDev)
	binary.Read(p, binary.BigEndian, &node.StIno)
	binary.Read(p, binary.BigEndian, &node.StNlink)
	binary.Read(p, binary.BigEndian, &node.StRdev)
	binary.Read(p, binary.BigEndian, &node.CtimeSec)
	binary.Read(p, binary.BigEndian, &node.CtimeNsec)
	binary.Read(p, binary.BigEndian, &node.CreateTimeSec)
	binary.Read(p, binary.BigEndian, &node.CreateTimeNsec)
	binary.Read(p, binary.BigEndian, &node.StBlocks)
	binary.Read(p, binary.BigEndian, &node.StBlksize)

	return
}
