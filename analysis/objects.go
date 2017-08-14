package analysis

import (
  "gopkg.in/cheggaaa/pb.v1"
  "log"
  "os"
  "bufio"
  "fmt"
  "strings"
  "github.com/penolver/gofwreview/parsers"
)

func ReviewObjects(rulebase map[int]parsers.FWRule,objects map[string]parsers.FWObj,objectgroups map[string]parsers.FWObjGroup,services map[string]parsers.FWSvc,servicegroups map[string]parsers.FWSvcGroup,filename string) {


  usedobjects := make(map[string]bool)
  unusedobjects := make(map[string]string)

  /*type FWObj struct {
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
  }*/

  log.Println("Analysing objects not used in groups..")

  bar := pb.StartNew(len(objectgroups))

  for _,value := range objectgroups {
    //log.Printf("key: %+v\n", key)
    //log.Printf("value: %+v\n", value)

    for _,valueobj := range value.FWObjs {


      usedobjects[valueobj] = true

      /*if _, ok := objects[valueobj]; ok {
        // exists

      } else {

      }*/
    }

    bar.Increment()

  }

  //for i := 0; i <= len(objectgroups); i++ {
      //rule := rulebase[i]

  //}

  bar.FinishPrint("Finished analysing Object groups")

  log.Println("Analysing rulebase..")

  bar = pb.StartNew(len(rulebase))

  for i := 0; i <= len(rulebase); i++ {
      rule := rulebase[i]

      // capture sources
      for _,valueobj := range rule.Sources {
        usedobjects[valueobj] = true
      }
      // and destinations
      for _,valueobj := range rule.Destinations {
        usedobjects[valueobj] = true
      }

      bar.Increment()
  }

  bar.FinishPrint("Finished analysing rulebase")

  log.Println("Finding unused object groups..")

  bar = pb.StartNew(len(objectgroups))

  for key,_ := range objectgroups {
    //log.Printf("key: %+v\n", key)
    //log.Printf("value: %+v\n", value)

      if _, ok := usedobjects[key]; ok {
        // used..

      } else {
        // not used..
        unusedobjects[key] = "address-set"
        //log.Println("unused object group: ",key)

      }


    bar.Increment()

  }

  bar.FinishPrint("Finished finding unused object groups")

  log.Println("Finding unused objects..")

  bar = pb.StartNew(len(objects))

  for key,_ := range objects {
    //log.Printf("key: %+v\n", key)
    //log.Printf("value: %+v\n", value)

      if _, ok := usedobjects[key]; ok {
        // used..

      } else {
        // not used..

        //but check is not a global object..
        theobj := strings.Split(key, ":")
        if _, ok := usedobjects["global:"+theobj[1]]; ok {
          // used..
        } else {
          unusedobjects[key] = "address"
          //log.Println("unused object: ",key)
        }

      }

    bar.Increment()

  }

  bar.FinishPrint("Finished finding unused objects")

  //return unusedobjects

  log.Println("Dumping unused objects to CSV..")
  bar = pb.StartNew(len(unusedobjects))

  var csvfile string
  csvfile = `object,object_type
  `

  for key,value := range unusedobjects {
    csvfile = csvfile+key+`,`+value+`
    `
    bar.Increment()
  }
  fileHandle, _ := os.Create(filename+".unusedobjects.csv")
  writer := bufio.NewWriter(fileHandle)
  defer fileHandle.Close()

  fmt.Fprint(writer, csvfile)
  writer.Flush()
  bar.FinishPrint("Finished writing CSV")

}
