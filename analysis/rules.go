package analysis

import (
  "gopkg.in/cheggaaa/pb.v1"
  "log"
  "os"
  "bufio"
  "fmt"
  "strings"
  "strconv"
  "github.com/penolver/gofwreview/parsers"
)

func ReviewRules(rulebase map[int]parsers.FWRule,filename string) {

  log.Println("Analysing rulebase and dumping to CSV..")

  bar := pb.StartNew(len(rulebase))

  var csvfile,anysource,anydest,anyservice,aaa,denywithoutlogging,sources,destinations,services string
  csvfile = `Rulename,Disabled,SourceZone,Sources,DestinationZone,Destinations,Services,Action,Protocol,Comments,Logging,Any-Source,Any-Destination,Any-Service,AAA,Potential-Further-Lockdown,Clear-Text-Protocols,Deny-without-Logging
  `

  for i := 0; i <= len(rulebase); i++ {
      //rule := rulebase[i]
      detail := rulebase[i]
      anysource = ""
      anydest = ""
      anyservice = ""
      aaa = ""
      denywithoutlogging = ""

      sources = `"`
      for _,source := range detail.Sources {
        sources = sources+strings.TrimSpace(source)+`
`
        thesource := strings.Split(source, ":")
        if thesource[1] == "Any" || thesource[1] == "any" || thesource[1] == "any-ipv4" {
          anysource = "yes"
        }
      }
      sources = sources+`"`
      destinations = `"`
      for _,destination := range detail.Destinations {
        destinations = destinations+strings.TrimSpace(destination)+`
`
        thedest := strings.Split(destination, ":")
        if thedest[1] == "Any" || thedest[1] == "any" || thedest[1] == "any-ipv4" {
          anydest = "yes"
        }
      }
      destinations = destinations+`"`
      services = `"`
      for _,service := range detail.Services {
        services = services+strings.TrimSpace(service)+`
`
        if service == "Any" || service == "any" {
          anyservice = "yes"
        }
      }
      services = services+`"`

      if anyservice == "yes" && anydest == "yes" && anysource == "yes" {
        aaa = "yes"
      }

      if detail.Allowdeny == "deny" && detail.Logging != "yes" {
        denywithoutlogging = "yes"
      }

      if detail.Allowdeny == "reject" && detail.Logging != "yes" {
        denywithoutlogging = "yes"
      }

      csvfile = csvfile+strings.TrimSpace(detail.RuleName)+`,`+strconv.FormatBool(detail.Disabled)+`,`+strings.TrimSpace(detail.SourceZone)+`,`+strings.TrimSpace(sources)+`,`+strings.TrimSpace(detail.DestinationZone)+`,`+strings.TrimSpace(destinations)+`,`+strings.TrimSpace(services)+`,`+strings.TrimSpace(detail.Allowdeny)+`,`+strings.TrimSpace(detail.Protocol)+`,`+strings.TrimSpace(detail.Comments)+`,`+(detail.Logging)+`,`+strings.TrimSpace(anysource)+`,`+strings.TrimSpace(anydest)+`,`+strings.TrimSpace(anyservice)+`,`+strings.TrimSpace(aaa)+`,,,`+strings.TrimSpace(denywithoutlogging)+`
      `
      bar.Increment()
  }

  bar.FinishPrint("Finished analysing rulebase")

  fileHandle, _ := os.Create(filename+".analysed-rulebase.csv")
  writer := bufio.NewWriter(fileHandle)
  defer fileHandle.Close()

  fmt.Fprint(writer, csvfile)
  writer.Flush()


}
