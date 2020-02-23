/*
arqinator: arq/types/s3.go
Implements S3 backup type for Arq.

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

package connector

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/urfave/cli"
	"strings"
)

type S3Connection struct {
	Connection     *s3.S3
	BucketName     string
	CacheDirectory string
	Downloader     *s3manager.Downloader
}

func (c S3Connection) String() string {
	return fmt.Sprintf("{S3Connection: BucketName=%s, CacheDirectory=%s",
		c.BucketName, c.CacheDirectory)
}

func NewS3Connection(c *cli.Context) (Connection, error) {
	//region := c.GlobalString("s3-region")
	s3BucketName := c.GlobalString("s3-bucket-name")
	cacheDirectory := c.GlobalString("cache-directory")
	//newSession := session.New(s3Config)
	s3Config := &aws.Config{
		//Credentials:      credentials.NewStaticCredentials("YOUR-ACCESSKEYID", "YOUR-SECRETACCESSKEY", ""),
		//Endpoint:         aws.String("http://localhost:9000"),
		Region: aws.String(c.GlobalString("s3-region")),
		//S3ForcePathStyle: aws.Bool(true),
	}
	if len(c.GlobalString("s3-endpoint")) != 0 {
		s3Config.Endpoint = aws.String(c.GlobalString("s3-endpoint"))
		if !strings.HasPrefix(c.GlobalString("s3-endpoint"), "https") {
			s3Config.DisableSSL = aws.Bool(true)
		}
		s3Config.S3ForcePathStyle = aws.Bool(true)
	}
	newSession := session.New(s3Config)

	svc := s3.New(newSession)

	conn := S3Connection{
		Connection:     svc,
		BucketName:     s3BucketName,
		CacheDirectory: cacheDirectory,
	}
	conn.Downloader = s3manager.NewDownloaderWithClient(svc)
	return conn, nil
}

func (c S3Connection) GetCacheDirectory() string {
	return c.CacheDirectory
}

func (c S3Connection) Close() error {
	return nil
}

type S3Object struct {
	S3FullPath string
}

func (s3Obj S3Object) String() string {
	return fmt.Sprintf("{S3Object: S3Object=%s}", s3Obj.S3FullPath)
}

func (s3Obj S3Object) GetPath() string {
	return s3Obj.S3FullPath
}

func (conn S3Connection) ListObjectsAsFolders(prefix string) ([]Object, error) {
	ret, err := conn.listObjects(prefix, "/")
	log.Debug(ret)
	return ret, err
}

func (conn S3Connection) ListObjectsAsAll(prefix string) ([]Object, error) {
	return conn.listObjects(prefix, "")
}

func (conn S3Connection) listObjects(prefix string, delimiter string) ([]Object, error) {
	s3Objs := make([]Object, 0)
	moreResults := false
	nextMarker := aws.String("")
	for {
		input := s3.ListObjectsInput{
			Bucket:    aws.String(conn.BucketName),
			Prefix:    aws.String(prefix),
			Delimiter: aws.String(delimiter),
		}
		if moreResults {
			input.Marker = nextMarker
		}
		log.Debug(input)
		result, err := conn.Connection.ListObjects(&input)
		if err != nil {
			log.Debugf("Failed to ListObjects for bucket %s, prefix %s: %s", conn.BucketName, prefix, err)
			return nil, err
		}
		if delimiter == "/" { // folders
			for _, commonPrefix := range result.CommonPrefixes {
				s3Obj := S3Object{
					S3FullPath: strings.TrimSuffix(*commonPrefix.Prefix, "/"),
				}
				s3Objs = append(s3Objs, s3Obj)
			}
		} else { // regular files
			for _, contents := range result.Contents {
				s3Obj := S3Object{
					S3FullPath: *contents.Key,
				}
				s3Objs = append(s3Objs, s3Obj)
			}
		}
		time.Sleep(100 * time.Millisecond)
		moreResults = *result.IsTruncated
		if moreResults {
			nextMarker = result.NextMarker
		} else {
			break
		}
	}
	return s3Objs, nil
}

func (conn S3Connection) getCacheFilepath(key string) (string, error) {
	cacheFilepath := filepath.Join(conn.GetCacheDirectory(), key)
	cacheFilepath, err := filepath.Abs(cacheFilepath)
	if err != nil {
		log.Debugf("Failed to make cacheFilepath %s absolute: %s",
			cacheFilepath, err)
		return "", err
	}
	return cacheFilepath, nil
}

func (conn S3Connection) CachedGet(key string) (string, error) {
	cacheFilepath, err := conn.getCacheFilepath(key)
	if err != nil {
		log.Debugf("Failed to getCacheFilepath in CachedGet: %s", err)
		return "", err
	}
	fileInfo, err := os.Stat(cacheFilepath)
	if err == nil && fileInfo.Size() != 0 {
		// file exists, so if it's zero-byte then we don't need to retrieve it again
		// however the file could still be corrupted. a connector cannot know if a file is corrupted or not,
		// it's up to callers to verify that downloaded files are uncorrupted.
		return cacheFilepath, nil
	}
	cacheFilepath, err = conn.Get(key)
	if err != nil {
		log.Debugln("Failed to cachedGet key: ", key)
		return cacheFilepath, err
	}
	return cacheFilepath, nil
}

func (conn S3Connection) Get(key string) (string, error) {
	cacheFilepath, err := conn.getCacheFilepath(key)
	if err != nil {
		log.Errorf("Failed to getCacheFilepath in Get: %s", err)
		return cacheFilepath, err
	}
	cacheDirectory := filepath.Dir(cacheFilepath)
	if err = os.MkdirAll(cacheDirectory, 0777); err != nil {
		log.Errorf("Couldn't create cache directory %s for cacheFilepath %s: %s",
			cacheDirectory, cacheFilepath, err)
		return cacheFilepath, err
	}
	if _, err = os.Stat(cacheDirectory); err != nil {
		log.Errorf("Cache directory %s doesn't exist!", cacheDirectory)
		return cacheFilepath, err
	}
	w, err := os.Create(cacheFilepath)
	if err != nil {
		log.Errorf("Couldn't create cache file for cacheFilepath %s: %s",
			cacheFilepath, err)
		return cacheFilepath, err
	}
	defer w.Close()
	_, err = conn.Downloader.Download(w, &s3.GetObjectInput{
		Bucket: aws.String(conn.BucketName),
		Key:    aws.String(key),
	})
	time.Sleep(100 * time.Millisecond)
	if err != nil {
		log.Errorf("Failed to download key: %s", err)
		defer os.Remove(cacheFilepath)
		return cacheFilepath, err
	}
	return cacheFilepath, nil
}
