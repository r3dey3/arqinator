package arq_types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
)

type CompressionType struct {
	Type int32
}

func (t CompressionType) String() string {
	return fmt.Sprintf("%d", t.Type)
}

func ReadCompressionType(p *bytes.Buffer, new_style bool) (compression_type *CompressionType, err error) {
	compression_type = &CompressionType{}
	if new_style {
		err = binary.Read(p, binary.BigEndian, &compression_type.Type)
		if err != nil {
			log.Debugf("ReadCompressionType failed to read int32: %s", err)
			return
		}
	} else {
		is_compressed, err2 := p.ReadByte()
		if err2 != nil {
			err = err2
			log.Debugf("ReadCompressionType failed to bool int32: %s", err)
			return
		}
		if is_compressed != 0 {
			compression_type.Type = 1
		}
	}
	return
}

func GzipCompression() (compression_type *CompressionType) {
	compression_type = &CompressionType{}
	compression_type.Type = 1
	return
}
