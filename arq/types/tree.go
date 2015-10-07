package arq_types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
)

type Tree struct {
	Header *Header

	// Only present for Tree v12 or later
	XattrsAreCompressed *Boolean

	// Only present for Tree v12 or later
	AclIsCompressed *Boolean

	XattrsBlobKey       *BlobKey
	XattrsSize          uint64
	AclBlobKey          *BlobKey
	Uid                 int32
	Gid                 int32
	Mode                int32
	MtimeSec            int64
	MtimeNsec           int64
	Flags               int64
	FinderFlags         int32
	ExtendedFinderFlags int32
	StDev               int32
	StIno               int32
	StNlink             uint32
	StRdev              int32
	CtimeSec            int64
	CtimeNsec           int64
	StBlocks            int64
	StBlksize           uint32

	// Only present for Tree v11 to v16
	AggregateSizeOnDisk uint64

	// Only present for Tree v15 or later
	CreateTimeSec int64

	// Only present for Tree v15 or later
	CreateTimeNsec int64

	// Only present for Tree v18 or later
	MissingNodes []*Node

	Nodes []*Node
}

func (c Tree) String() string {
	return fmt.Sprintf("{Tree: Header=%s, XattrsAreCompressed=%s, "+
		"AclIsCompressed=%s, XattrsBlobKey=%s, XattrsSize=%d, "+
		"AclBlobKey=%s, Uid=%d, Gid=%d, Mode=%d, MtimeSec=%d, MtimeNsec=%d, "+
		"Flags=%x, FinderFlags=%x, ExtendedFinderFlags=%x, StDev=%d, "+
		"StIno=%d, StNlink=%d, StRdev=%d, CtimeSec=%d, CtimeNsec=%d, "+
		"StBlocks=%d, StBlksize=%d, AggregateSizeOnDisk=%d, "+
		"CreateTimeSec=%d, CreateTimeNsec=%d, MissingNodes=%s}",
		c.Header, c.XattrsAreCompressed, c.AclIsCompressed, c.XattrsBlobKey,
		c.XattrsSize, c.AclBlobKey, c.Uid, c.Gid, c.Mode, c.MtimeSec,
		c.MtimeNsec, c.Flags, c.FinderFlags, c.ExtendedFinderFlags,
		c.StDev, c.StIno, c.StNlink, c.StRdev, c.CtimeSec, c.CtimeNsec,
		c.StBlocks, c.StBlksize, c.AggregateSizeOnDisk, c.CreateTimeSec,
		c.CreateTimeNsec, c.MissingNodes)
}

func ReadTree(p *bytes.Buffer) (tree *Tree, err error) {
	tree = &Tree{}
	if tree.Header, err = ReadHeader(p); err != nil {
		err = errors.New(fmt.Sprintf("ReadTree header couldn't be parsed: %s", err))
		return
	}
	if tree.Header.Version >= 12 {
		if tree.XattrsAreCompressed, err = ReadBoolean(p); err != nil {
			err = errors.New(fmt.Sprintf("ReadTree failed during XattrsAreCompressed parsing: %s", err))
			return
		}
		if tree.AclIsCompressed, err = ReadBoolean(p); err != nil {
			err = errors.New(fmt.Sprintf("ReadTree failed during AclIsCompressed parsing: %s", err))
			return
		}
	}
	log.Printf("Reading XattrsBlobKey...")
	if tree.XattrsBlobKey, err = ReadBlobKey(p, tree.Header, true); err != nil {
		err = errors.New(fmt.Sprintf("ReadTree XattrsBlobKey couldn't be parsed: %s", err))
		return
	}
	if tree.XattrsBlobKey.SHA1 == nil {
		tree.XattrsBlobKey = nil
	}
	binary.Read(p, binary.BigEndian, &tree.XattrsSize)
	log.Printf("Reading AclBlobKey...")
	if tree.AclBlobKey, err = ReadBlobKey(p, tree.Header, true); err != nil {
		err = errors.New(fmt.Sprintf("ReadTree AclBlobKey couldn't be parsed: %s", err))
		return
	}
	if tree.AclBlobKey.SHA1 == nil {
		tree.AclBlobKey = nil
	}
	binary.Read(p, binary.BigEndian, &tree.Uid)
	binary.Read(p, binary.BigEndian, &tree.Gid)
	binary.Read(p, binary.BigEndian, &tree.Mode)
	binary.Read(p, binary.BigEndian, &tree.MtimeSec)
	binary.Read(p, binary.BigEndian, &tree.MtimeNsec)
	binary.Read(p, binary.BigEndian, &tree.Flags)
	binary.Read(p, binary.BigEndian, &tree.FinderFlags)
	binary.Read(p, binary.BigEndian, &tree.ExtendedFinderFlags)
	binary.Read(p, binary.BigEndian, &tree.StDev)
	binary.Read(p, binary.BigEndian, &tree.StIno)
	binary.Read(p, binary.BigEndian, &tree.StNlink)
	binary.Read(p, binary.BigEndian, &tree.StRdev)
	binary.Read(p, binary.BigEndian, &tree.CtimeSec)
	binary.Read(p, binary.BigEndian, &tree.CtimeNsec)
	binary.Read(p, binary.BigEndian, &tree.StBlocks)
	binary.Read(p, binary.BigEndian, &tree.StBlksize)
	if tree.Header.Version >= 11 && tree.Header.Version <= 16 {
		binary.Read(p, binary.BigEndian, &tree.AggregateSizeOnDisk)
	}
	if tree.Header.Version >= 15 {
		binary.Read(p, binary.BigEndian, &tree.CreateTimeSec)
		binary.Read(p, binary.BigEndian, &tree.CreateTimeNsec)
	}
	if tree.Header.Version >= 18 {
		log.Printf("Reading MissingNodes...")
		if tree.MissingNodes, err = ReadNodes(p, tree.Header); err != nil {
			err = errors.New(fmt.Sprintf("ReadTree MissingNodes couldn't be parsed: %s", err))
			return
		}
	}
	log.Printf("Reading Nodes...")
	if tree.Nodes, err = ReadNodes(p, tree.Header); err != nil {
		err = errors.New(fmt.Sprintf("ReadTree Nodes couldn't be parsed: %s", err))
		return
	}
	return
}