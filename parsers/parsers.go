package parsers

import (
  //"bufio"
  "log"
  //"fmt"
  "os"
  //"flag"
  //"regexp"
  "bytes"
  "io"
  //"strings"
)

type FWRule struct {
  RuleName string
  Allowdeny string
  Disabled  bool
  SourceZone string
  Sources []string
  DestinationZone string
  Destinations []string
  Services []string
  Protocol  string
  Comments  string
  Logging  string
  Misc  string
}

type FWObj struct {
  FWObjName string
  IP string
  Mask string
  Comment string
  Zone  string
}

type FWObjGroup struct {
  FWObjGroupName string
  FWObjGroupType string
  FWObjs []string
  Comment string
}

type FWSvc struct {
  FWSvcName string
  FWSvcType string
  Service string
  Protocol  string
  Comment string
}

type FWSvcGroup struct {
  FWSvcGroupName string
  FWSvcGroupType string
  Services []string
  Comment string
}

// count number of lines in file
func LineCounter(path string) (int, error) {
    buf := make([]byte, 32*1024)
    count := 0
    lineSep := []byte{'\n'}

    r, err := os.Open(path)
  	if err != nil {
  		log.Fatal("File Missing. ", err)
  	}

    for {
        c, err := r.Read(buf)
        count += bytes.Count(buf[:c], lineSep)

        switch {
        case err == io.EOF:
            return count, nil

        case err != nil:
            return count, err
        }
    }
} // LineCounter
