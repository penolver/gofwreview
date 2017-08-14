package main

import (
  "bufio"
  "log"
  "fmt"
  "flag"
  "github.com/penolver/gofwreview/parsers"
  "github.com/penolver/gofwreview/analysis"
  "os"
  "strings"
  "strconv"
  "gopkg.in/cheggaaa/pb.v1"
)

const version = "0.0.2"

func main() {

  fmt.Println(`
              _____      __             _
   ___ ____  / __/ | /| / /______ _  __(_)__ _    __
  / _  / _ \/ _/ | |/ |/ / __/ -_) |/ / / -_) |/|/ /
  \_, /\___/_/   |__/|__/_/  \__/|___/_/\__/|__,__/
 /___/   version `+version+`
  `)

  // log file to process
  configPtr := flag.String("c", "config.txt", "the source config file, e.g. `config.txt`")
  typePtr := flag.String("t", "vendor", "the source config file type, e.g. `vendor`, valid types include srx (only currently)")
  csvDumpFlag := flag.Bool("x", false, "export to CSV, named same as config file but with .csv")

  flag.Parse()


  if *configPtr == "config.txt" {
    //log.Println("ERROR, please provide flags.")
    flag.PrintDefaults()
    fmt.Println()
    log.Fatal("ERROR, missing arguments")
  }
  if *typePtr == "vendor" {
    //log.Println("ERROR, please provide flags.")
    flag.PrintDefaults()
    fmt.Println()
    log.Fatal("ERROR, missing arguments")
  }

  rules := make(map[int]parsers.FWRule)
  objects := make(map[string]parsers.FWObj)
  objectgroup := make(map[string]parsers.FWObjGroup)
  services := make(map[string]parsers.FWSvc)
  servicegroup := make(map[string]parsers.FWSvcGroup)

  //ruletracker := make(map[int]string)
  if *typePtr == "srx" {
    log.Println("Processing SRX config..")
    rules,objects,objectgroup,services,servicegroup = parsers.ParseSRXSet(*configPtr)
  }else {
    log.Fatal("Unsupported config type, exiting.")
  }


  if *csvDumpFlag == true {

    // dump rulebase to CSV

    log.Println("Dumping rules to CSV..")
    bar := pb.StartNew(len(rules))


    var csvfile string
    csvfile = `Rulename,Disabled,SourceZone,Sources,DestinationZone,Destinations,Services,Action,Protocol,Comments,Logging,Misc
    `

    for i := 0; i <= len(rules); i++ {
        //fmt.Println(string(value[i]))
        detail := rules[i]

    //}

  
      var sources,destinations,services string

      sources = `"`
      for _,source := range detail.Sources {
        sources = sources+strings.TrimSpace(source)+`
`
      }
      sources = sources+`"`
      destinations = `"`
      for _,destination := range detail.Destinations {
        destinations = destinations+strings.TrimSpace(destination)+`
`
      }
      destinations = destinations+`"`
      services = `"`
      for _,service := range detail.Services {
        services = services+strings.TrimSpace(service)+`
`
      }
      services = services+`"`

      csvfile = csvfile+strings.TrimSpace(detail.RuleName)+`,`+strconv.FormatBool(detail.Disabled)+`,`+strings.TrimSpace(detail.SourceZone)+`,`+strings.TrimSpace(sources)+`,`+strings.TrimSpace(detail.DestinationZone)+`,`+strings.TrimSpace(destinations)+`,`+strings.TrimSpace(services)+`,`+strings.TrimSpace(detail.Allowdeny)+`,`+strings.TrimSpace(detail.Protocol)+`,`+strings.TrimSpace(detail.Comments)+`,`+(detail.Logging)+`,`+strings.TrimSpace(detail.Misc)+`
      `
      bar.Increment()
    }

    fileHandle, _ := os.Create(*configPtr+".rulebase.csv")
    writer := bufio.NewWriter(fileHandle)
    defer fileHandle.Close()

    fmt.Fprint(writer, csvfile)
    writer.Flush()
    bar.FinishPrint("Finished writing CSV")

  }

  // analyse objects
  analysis.ReviewObjects(rules,objects,objectgroup,services,servicegroup,*configPtr)


  analysis.ReviewRules(rules,*configPtr)

}
