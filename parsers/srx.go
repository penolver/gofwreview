package parsers

import (
  "gopkg.in/cheggaaa/pb.v1"
  "log"
  "os"
  "bufio"
  "strings"
)

func ParseSRXSet(filename string) (map[int]FWRule,map[string]FWObj,map[string]FWObjGroup,map[string]FWSvc,map[string]FWSvcGroup) {

  linesinfile,_ := LineCounter(filename)
  log.Println("Lines inconfig to process: ",linesinfile)
  log.Println("Processing SRX config file...")

  bar := pb.StartNew(linesinfile)

  file, err := os.Open(filename)
  if err != nil {
    // err is printable
    // elements passed are separated by space automatically
    log.Fatal("Error:", err)
    //return nil, nil, nil, nil
  }
  // automatically call Close() at the end of current method
  defer file.Close()
  // create a new scanner and read the file line by line
  scanner := bufio.NewScanner(file)

  // hash map to store the rules
  rules := make(map[int]FWRule)

  // hash map to store the rule groups
  rulegroups := make(map[string]map[int]FWRule)

  // hash map to store the objects
  objects := make(map[string]FWObj)
  objectgroup := make(map[string]FWObjGroup)
  services := make(map[string]FWSvc)
  servicegroup := make(map[string]FWSvcGroup)

  //rules := make(map[string]FWRule)
  var counter,rulegroupcounter int
  //ruletracker := make(map[int]string)
  var currentrulename,currentrulegroup,currentrulegrouppolicy string
  var rule,rulegroup FWRule

  for scanner.Scan() {
    //log.Println("line is: ",scanner.Text())

    //log.Println("DEBUG: line processing.. ",scanner.Text())
    line := strings.Split(scanner.Text(), " ")

    // if we're dealing with an application
    if line[0] == "set" && line[1] == "applications" && line[2] == "application" {

      service := services[line[3]]



      service.FWSvcName = line[3]
      //service.FWSvcType = line[10]

      if line[4] == "term" && line[6] == "destination-port" {
        service.Service = line[7]
      }
      if line[4] == "term" && line[6] == "protocol" {
        service.Protocol = line[7]
      }

      services[line[3]] = service

    }

    // if we're dealing with an set application set
    if line[0] == "set" && line[1] == "applications" && line[2] == "application-set" {

      //var fwobjgroup FWObjGroup

      appgroup := servicegroup[line[3]]


      appgroup.FWSvcGroupName = line[3]
      appgroup.FWSvcGroupType = "application-set"
      appgroup.Services = append(appgroup.Services,line[5])

      servicegroup[line[3]] = appgroup

    }


    // if we're dealing with an set group object
    if len(line) > 8 && line[0] == "set" && line[1] == "groups" && line[7] == "address-book" && line[8] == "address" {

      var fwobj FWObj

      fwobj.FWObjName = line[9]
      fwobj.IP = line[10]
      fwobj.Zone = "global"

      objects["global:"+line[9]] = fwobj


    }

    // if we're dealing with an set group address-set
    if len(line) > 8 && line[0] == "set" && line[1] == "groups" && line[7] == "address-book" && line[8] == "address-set" {

      //var fwobjgroup FWObjGroup

      group := objectgroup["global:"+line[9]]


      group.FWObjGroupName = line[9]
      group.FWObjGroupType = "address-set"
      group.FWObjs = append(group.FWObjs,"global:"+line[11])

      objectgroup["global:"+line[9]] = group

    }

    // if we're dealing with an set security address object
    if line[0] == "set" && line[1] == "security" && line[2] == "zones" && line[5] == "address-book" && line[6] == "address" {

      var fwobj FWObj

      fwobj.FWObjName = line[7]

      if line[8] == "dns-name" {
        fwobj.IP = line[9]
      }else {
        fwobj.IP = line[8]
      }

      fwobj.IP = line[8]
      fwobj.Zone = line[4]

      objects[line[4]+":"+line[7]] = fwobj


    }

    // if we're dealing with an set security address-set object
    if line[0] == "set" && line[1] == "security" && line[2] == "zones" && line[5] == "address-book" && line[6] == "address-set" {

      //var fwobjgroup FWObjGroup

    //  log.Println("DEBUG: in group.. ",scanner.Text())

      group := objectgroup[line[4]+":"+line[7]]


      group.FWObjGroupName = line[7]
      group.FWObjGroupType = "address-set"
      //group.Comment = line[8]
      group.FWObjs = append(group.FWObjs,line[4]+":"+line[9])



      objectgroup[line[4]+":"+line[7]] = group


    }




    // if we're dealing with a rule group
    if line[0] == "set" && line[1] == "groups" && line[3] == "security" && line[4] == "policies" {


      // TODO: need to re work this to have nested ordered ruleset within a group map..

      if currentrulegroup != line[2] {
        currentrulegroup = line[2]
        rulegroupcounter = 0
        rulegroups[currentrulegroup] = make(map[int]FWRule)
      }

      if currentrulegrouppolicy != line[10] {
        rulegroupcounter++
        currentrulegrouppolicy = line[10]
        // reinitalise the rulegroup var
        // probbaly not the go way, but cant figure out how to reinitalise without creating new..
        var newrulegroup FWRule
        rulegroup = newrulegroup
      }

      rulegroup = rulegroups[currentrulegroup][rulegroupcounter]

      rulegroup.SourceZone = line[6]
      rulegroup.DestinationZone = line[8]

      rulegroup.RuleName = "rule-group:"+line[2]+"-"+line[10]

      if line[11] == "match" {
          if line[12] == "source-address" {
            if line[6] == "<*>" {
              rulegroup.Sources = append(rulegroup.Sources,"global:"+line[13])
            }else {
              rulegroup.Sources = append(rulegroup.Sources,line[6]+":"+line[13])
            }

          }
          if line[12] == "destination-address" {
            if line[8] == "<*>" {
              rulegroup.Destinations = append(rulegroup.Destinations,"global:"+line[13])
            }else {
              rulegroup.Destinations = append(rulegroup.Destinations,line[8]+":"+line[13])
            }
          }
          if line[12] == "application" {
            rulegroup.Services = append(rulegroup.Services,line[13])
          }

      }

      if line[11] == "then" {
        if line[12] == "permit" {
          rulegroup.Allowdeny = "allow"
        }
        if line[12] == "reject" {
          rulegroup.Allowdeny = "reject"
        }
        if line[12] == "deny" {
          rulegroup.Allowdeny = "deny"
        }
        if line[12] == "log" {
          rulegroup.Logging = "yes"
        }

      }

      rulegroups[currentrulegroup][rulegroupcounter] = rulegroup

    }



    // if we're dealing with a rule..
    if line[0] == "set" && line[1] == "security" && line[2] == "policies" {

      rule = rules[counter]

      rule.SourceZone = line[4]
      rule.DestinationZone = line[6]

      if line[7] == "policy" {

        // if a new rule we keep track (note that hash maps in Go do not retain order, hence we track)
        if currentrulename != line[8] {
          counter++
          //ruletracker[counter] = line[8]
          currentrulename = line[8]
          // reinitalise the rule var
          // probbaly not the go way, but cant figure out how to reinitalise without creating new..
          var newrule FWRule
          rule = newrule
        }

        rule.RuleName = line[8]



        if line[9] == "match" {
            if line[10] == "source-address" {
              rule.Sources = append(rule.Sources,strings.TrimSpace(line[4]+":"+line[11]))
            }
            if line[10] == "destination-address" {
              rule.Destinations = append(rule.Destinations,strings.TrimSpace(line[6]+":"+line[11]))
            }
            if line[10] == "application" {
              rule.Services = append(rule.Services,strings.TrimSpace(line[11]))
            }

        }

        if line[9] == "then" {
          if line[10] == "permit" {
            rule.Allowdeny = "permit"
          }
          if line[10] == "reject" {
            rule.Allowdeny = "reject"
          }
          if line[10] == "deny" {
            rule.Allowdeny = "deny"
          }
          if line[10] == "log" {
            rule.Logging = "yes"
          }

        }
        if line[9] == "description" {
          desc := strings.Split(scanner.Text(), "\"")
            rule.Comments = desc[1]
        }
      }
      if line[7] == "apply-groups" {

          // if rule group exists..
          if _, ok := rulegroups[line[8]]; ok {
            for i := 0; i <= len(rulegroups[line[8]]); i++ {
                //fmt.Println(string(value[i]))
                //detail := rules[i]
                rule := rulegroups[line[8]][i]
                if rule.SourceZone == "<*>" {
                  rule.SourceZone = line[4]+" (apply group "+line[8]+" original zone "+rule.SourceZone+")"
                  rule.DestinationZone = rule.DestinationZone+" (apply group "+line[8]+" proposed zone "+line[6]+")"
                }
                if rule.DestinationZone == "<*>" {
                  rule.DestinationZone = line[6]+" (apply group "+line[8]+" original zone "+rule.DestinationZone+")"
                  rule.SourceZone = rule.SourceZone+" (apply group "+line[8]+" proposed zone "+line[4]+")"
                }
                if rule.SourceZone == "<*>" && rule.DestinationZone == "<*>" {
                  rule.SourceZone = line[4]+" (apply group "+line[8]+" original zone "+rule.SourceZone+")"
                  rule.DestinationZone = line[6]+" (apply group "+line[8]+" original zone "+rule.DestinationZone+")"
                }
                rules[counter] = rule
                counter++
            }
          }else {
            // just increment counter
            counter++
          }



      }


      // add rule data into rules
      rules[counter] = rule

    }

    // if we're dealing with a disabled rule..
    if line[0] == "deactivate" && line[1] == "security" && line[2] == "policies" {

      rule = rules[counter]

      if rule.RuleName == line[8] && rule.SourceZone == line[4] && rule.DestinationZone == line[6] {
        rule.Disabled = true
        rules[counter] = rule
      }

    }


    bar.Increment()
  }
  bar.FinishPrint("Finished Processing and Analysing Config")

  //log.Println("objects returned.. ",len(objects))

  return rules,objects,objectgroup,services,servicegroup

}
