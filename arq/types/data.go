/*
arqinator: arq/types/data.go
Implements an Arq Data.

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
	"fmt"
	log "github.com/sirupsen/logrus"
)

type Data struct {
	IsPresent bool
	Data      []byte
}

func (d Data) String() string {
	if !d.IsPresent {
		return "<nil>"
	}
	return fmt.Sprintf("%s", d.Data)
}

func ReadData(p *bytes.Buffer) (data *Data, err error) {
	data = &Data{}
	var length uint64
	err = binary.Read(p, binary.BigEndian, &length)
	if err != nil {
		log.Debugf("ReadData failed during read of length %d: %s",
			length, err)
		return
	}
	data.IsPresent = true
	data.Data = p.Next(int(length))
	return
}
