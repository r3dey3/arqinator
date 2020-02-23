/*
arqinator: arq/types/backup_set.go
Implements an ArqBackupSet, a high level entry point to Arq backups.

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

package arq

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"

	"github.com/mattn/go-plist"

	"github.com/asimihsan/arqinator/connector"
	"github.com/asimihsan/arqinator/crypto"
	"strings"
)

var (
	UUID_REGEXP = regexp.MustCompile("[a-zA-Z0-9-]{32,}")
)

type ArqBackupSet struct {
	Connection   connector.Connection
	UUID         string
	ComputerInfo *ArqComputerInfo
	Buckets      []*ArqBucket
	Decrypter    *crypto.CryptoState
}

func GetArqBackupSets(connection connector.Connection, password []byte) ([]*ArqBackupSet, error) {
	prefix := ""
	objects, err := connection.ListObjectsAsFolders(prefix)
	if err != nil {
		log.Debugln("Failed to get buckets for GetArqBackupSets: ", err)
		return nil, err
	}
	arqBackupSets := make([]*ArqBackupSet, 0)
	for _, object := range objects {
		if !UUID_REGEXP.MatchString(object.GetPath()) {
			log.Debugf("folder %s is not UUID, can't be backup set, so skipping", object.GetPath())
			continue
		}
		arqBackupSet, err := NewArqBackupSet(connection, password, object.GetPath())
		if err != nil {
			log.Debugf("Error during GetArqBackupSets for object %s: %s", object, err)
			continue
		}
		arqBackupSets = append(arqBackupSets, arqBackupSet)
	}
	return arqBackupSets, nil
}

func NewArqBackupSet(connection connector.Connection, password []byte, uuid string) (*ArqBackupSet, error) {
	var err error
	abs := ArqBackupSet{
		Connection: connection,
		UUID:       uuid,
	}

	// Regular objects (commits, trees, blobs) use a random "salt" stored in backup
	var encDatFile []byte
	if encDatFile, err = abs.getEncDatFile(); err != nil {
		log.Debugln("Failed during NewArqBackupSet getSalt: ", err)
		return nil, err
	}
	if abs.Decrypter, err = crypto.NewCryptoState(password, encDatFile); err != nil {
		log.Debugln("Failed during NewArqBackupSet NewCryptoState for Decrypter: ", err)
		return nil, err
	}

	// Arq Buckets (the folders) use a fixed salt. See arq_restore/Bucket.m.
	if abs.ComputerInfo, err = abs.getComputerInfo(); err != nil {
		log.Debugln("Failed during NewArqBackupSet getComputerInfo: ", err)
		return nil, err
	}

	if abs.Buckets, err = abs.getBuckets(); err != nil {
		log.Debugln("Failed during NewArqBackupSet getBuckets: ", err)
		return nil, err
	}

	return &abs, nil
}

func (abs ArqBackupSet) String() string {
	return fmt.Sprintf("{ArqBackupSet: Connection=%s, UUID=%s, ComputerInfo=%s, Buckets=%s}",
		abs.Connection, abs.UUID, abs.ComputerInfo, abs.Buckets)
}

type ArqComputerInfo struct {
	UserName     string
	ComputerName string
}

func (aci ArqComputerInfo) String() string {
	return fmt.Sprintf("{ArqComputerInfo: UserName=%s, ComputerName=%s}", aci.UserName, aci.ComputerName)
}

func (abs *ArqBackupSet) getEncDatFile() ([]byte, error) {
	key := abs.UUID + "/encryptionv3.dat"
	filepath, err := abs.Connection.CachedGet(key)
	if err != nil {
		log.Debugln("Failed to get salt", err)
		return nil, err
	}
	datfile, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Debugln("Failed to read salt from file: ", err)
		return nil, err
	}
	return datfile, err
}

func (abs *ArqBackupSet) getComputerInfo() (*ArqComputerInfo, error) {
	key := abs.UUID + "/computerinfo"
	filepath, err := abs.Connection.CachedGet(key)
	if err != nil {
		log.Debugln("Failed to get computerinfo", err)
		return nil, err
	}
	r, err := os.Open(filepath)
	if err != nil {
		log.Debugln("Failed to open computerinfo on disk")
		return nil, err
	}
	defer r.Close()
	v, err := plist.Read(r)
	if err != nil {
		log.Debugln("Could not decode computerInfo", err)
		return nil, err
	}
	tree := v.(plist.Dict)
	return &ArqComputerInfo{
		UserName:     tree["userName"].(string),
		ComputerName: tree["computerName"].(string),
	}, nil
}

func (abs *ArqBackupSet) CacheTreePackSets() error {
	log.Debugln("CacheTreePackSets entry for ArqBackupSet: ", abs)
	defer log.Debugln("CacheTreePackSets exit for ArqBackupSet: ", abs)
	for i := range abs.Buckets {
		abs.cacheTreePackSet(abs.Buckets[i])
	}
	return nil
}

func (abs *ArqBackupSet) CacheBlobPackSets() error {
	log.Debugln("CacheBlobPackSets entry for ArqBackupSet: ", abs)
	defer log.Debugln("CacheBlobPackSets exit for ArqBackupSet: ", abs)
	for i := range abs.Buckets {
		abs.cacheBlobPackSet(abs.Buckets[i])
	}
	return nil
}

func (abs *ArqBackupSet) cacheBlobPackSet(ab *ArqBucket) error {
	prefix := GetPathToBucketPackSetBlobs(abs, ab)
	return abs.cachePackSet(ab, prefix)
}

func (abs *ArqBackupSet) cacheTreePackSet(ab *ArqBucket) error {
	prefix := GetPathToBucketPackSetTrees(abs, ab)
	return abs.cachePackSet(ab, prefix)
}

func (abs *ArqBackupSet) cachePackSet(ab *ArqBucket, prefix string) error {
	s3Objs, err := abs.Connection.ListObjectsAsAll(prefix)
	if err != nil {
		log.Debugln("Failed to cacheTreePackSet for bucket: ", ab)
		log.Debugln(err)
		return err
	}
	inputs := make(chan connector.Object, len(s3Objs))
	for i := range s3Objs {
		inputs <- s3Objs[i]
	}
	close(inputs)
	log.Debugln("cachePackSet using concurrency of: ", runtime.GOMAXPROCS(0)*2)
	c := make(chan int, runtime.GOMAXPROCS(0)*2)
	for i := 0; i < cap(c); i++ {
		go func() {
			defer func() { c <- 1 }()
			for inputObject := range inputs {
				log.Debugln("cachePackSet considering: ", inputObject.GetPath())
				if !strings.HasSuffix(inputObject.GetPath(), ".index") {
					log.Debugln("cachePackSet rejects file, not a pack set")
					continue
				}
				log.Debugln("cachePackSet will cache: ", inputObject.GetPath())

				// here we request that the connector either download the file to the cache or ensure
				// that the cached copy already exists. the connector promises to try to download the
				// file, but cannot guarantee the file will be uncorrupted. it's up to us to verify
				// that.
				cacheFilepath, err := abs.Connection.CachedGet(inputObject.GetPath())
				if err != nil {
					log.Debugln("cachePackSet failed first time to get object: ", inputObject)
					log.Debugln(err)
				}

				isValid, err := IsValidPackFile(cacheFilepath)
				if !isValid {
					log.Debugf("cachePackSet invalid pack file %s first time, will delete and retry. err: %s", cacheFilepath, err)
					if err := os.Remove(cacheFilepath); err != nil {
						log.Panicf("cachePackSet failed to delete pack file %s after detecting corruption. err: ", cacheFilepath, err)
					}
					cacheFilepath, err = abs.Connection.CachedGet(inputObject.GetPath())
					if err != nil {
						log.Debugf("cachePackSet failed second time to get object: ", inputObject)
						log.Debugln(err)
					}
					isValid, err := IsValidPackFile(cacheFilepath)
					if !isValid {
						msg := fmt.Sprintf("cachePackSet invalid pack file %s second time, will not retry. err: %s", cacheFilepath, err)
						log.Panicln(msg)
					}
				}
			}
		}()
	}
	for i := 0; i < cap(c); i++ {
		<-c
	}
	return nil
}

func (abs *ArqBackupSet) getBuckets() ([]*ArqBucket, error) {
	prefix := abs.UUID + "/buckets"
	objects, err := abs.Connection.ListObjectsAsAll(prefix)
	if err != nil {
		log.Debugln("Failed to get buckets for ArqBackupSet: ", err)
		return nil, err
	}
	buckets := make([]*ArqBucket, 0)
	for _, object := range objects {
		bucket, err := NewArqBucket(object, abs)
		if err != nil {
			log.Debugln("Failed to get ArqBucket for object: ", object)
			log.Debugln(err)
			return nil, err
		}
		buckets = append(buckets, bucket)
	}
	return buckets, nil
}
