var exports = module.exports = {};

var esprima = require('esprima');

// JSON Schema validation
var tv4 = require('tv4');

// Writing JSON file to file system
var fs = require('fs');

var debug = true;

function dlog(msg) {
  if (debug) {
    console.log(msg)
  }
}

var threatspecSchema = {
  "schema": "http://json-schema.org/draft-04/schema#",
  "title": "threatspec_schema_strict",
  "type": "object",
  "required": ["specification", "boundaries", "components", "threats", "projects"],
  "additionalProperties": false,
  "definitions": {
    "id": {
      "type": "string",
      "pattern": "^@[a-zA-Z0-9_]+$"
    },
    "references": {
      "type": "array",
      "items": { "type": "string" },
      "uniqueItems": true
    },
    "source": {
      "type": "object",
      "required": ["function","file","line"],
      "additionalProperties": false,
      "properties": {
        "function": { "type": "string" },
        "file": { "type": "string" },
        "line": { "type": "integer" }
      }
    },
    "call": {
      "type":"object",
      "required": ["source","destination"],
      "additionalProperties": false,
      "properties": {
        "source": { "type": "string" },
        "destination": { "type": "string" }
      }
    }
  },
  "properties": {
    "specification": {
      "type": "object",
      "required": ["name", "version"],
      "additionalProperties": false,
      "properties": {
        "name": { "type": "string", "pattern": "^ThreatSpec$" },
        "version": { "type": "string", "pattern": "^0\\.[0-9]+\\.[0-9]+$" }
      }
    },
    "document": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "created": { "type": "integer" },
        "updated": { "type": "integer" }
      }
    },
    "boundaries": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" }
          }
        }
      }
    },
    "components": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" }
          }
        }
      }
    },
    "threats": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" },
            "references": { "$ref": "#/definitions/references" }
          }
        }
      }
    },
    "projects": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "required": ["mitigations", "exposures", "transfers", "acceptances"],
          "properties": {
            "mitigations": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["mitigation","boundary","component","threat"],
                    "properities": {
                      "mitigation": { "type": "string" },
                      "boundary": { "$ref": "#/definitions/id" },
                      "component": { "$ref": "#/definitions/id" },
                      "threat": { "$ref": "#/definitions/id" },
                      "references": { "$ref": "#/definitions/references" },
                      "source": { "$ref": "#/definitions/source" }
                    }
                  }
                }
              }
            },
            "exposures": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["exposure","boundary","component","threat"],
                    "properities": {
                      "exposure": { "type": "string" },
                      "boundary": { "$ref": "#/definitions/id" },
                      "component": { "$ref": "#/definitions/id" },
                      "threat": { "$ref": "#/definitions/id" },
                      "references": { "$ref": "#/definitions/references" },
                      "source": { "$ref": "#/definitions/source" }
                    }
                  }
                }
              }
            },
            "transfers": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["transfer","boundary","component","threat"],
                    "properities": {
                      "transfer": { "type": "string" },
                      "boundary": { "$ref": "#/definitions/id" },
                      "component": { "$ref": "#/definitions/id" },
                      "threat": { "$ref": "#/definitions/id" },
                      "references": { "$ref": "#/definitions/references" },
                      "source": { "$ref": "#/definitions/source" }
                    }
                  }
                }
              }
            },
            "acceptances": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["acceptance","boundary","component","threat"],
                    "properities": {
                      "acceptance": { "type": "string" },
                      "boundary": { "$ref": "#/definitions/id" },
                      "component": { "$ref": "#/definitions/id" },
                      "threat": { "$ref": "#/definitions/id" },
                      "references": { "$ref": "#/definitions/references" },
                      "source": { "$ref": "#/definitions/source" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "callflow": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/call"
      }
    }
  }
}

var keyLookup = {
  "threat": "threats",
  "boundary": "boundaries",
  "component": "components"
}

var idCleanPattern = /[^a-zA-Z0-9 ]+/g
var idSpacePattern = /\s+/g
var globalPattern = /^(?:[\s\*]*)@(alias)/i
var morePattern = /^\s*(.+?)(?:\s*\((.*?)\)|(\\))?\s*$/i
var describePattern = /^(?:[\s\*]*)@describe (boundary|component|threat) (\@[a-z0-9_]+?) as (.+?)(\\)?\s*$/i
var aliasPattern = /^(?:[\s\*]*)@alias (boundary|component|threat) (\@[a-z0-9_]+?) to (.+?)(\\)?\s*$/i
var tagPattern = /^(?:[\s\*]*)@(mitigates|exposes|transfers|accepts|alias|describe)/i
var mitigationPattern = /^(?:[\s\*]*)@mitigates (.+?):(.+?) against (.+?) with (.+?)(?:\s*\((.*?)\)|(\\))?\s*$/i
var exposurePattern = /^(?:[\s\*]*)@exposes (.+?):(.+?) to (.+?) with (.+?)(?:\s*\((.*?)\)|(\\))?\s*$/i
var transferPattern = /^(?:[\s\*]*)@transfers (.+?) to (.+?):(.+?) with (.+?)(?:\s*\((.*?)\)|(\\))?\s*$/i
var acceptancePattern = /^(?:[\s\*]*)@accepts (.+?) to (.+?):(.+?) with (.+?)(?:\s*\((.*?)\)|(\\))?\s*$/i

var project = "default"

var data = {}

function resetData() {
  data = {
    "specification": {
      "name": "ThreatSpec",
      "version": "0.1.0"
    },
    "document": {
      "created": Math.floor(Date.now() / 1000),
      "updated": Math.floor(Date.now() / 1000)
    },
    "boundaries": {},
    "components": {},
    "threats": {},
    "projects": {}
  }

  data["projects"][project] = {
    "mitigations":{},
    "exposures": {},
    "transfers": {},
    "acceptances": {}
  }
}

function toId(name) {
  if (name == "") {
   return ""
  }

  if (name.substring(0,1) == "@") {
    return name
  }

  return "@" + name.replace(idCleanPattern, "").replace(idSpacePattern, "_").toLowerCase();
}

function addBoundary(id, boundary) {
  if (id == "") {
    id = toId(boundary)
  }

  if (boundary == "") {
    return ""
  }

  if (! data["boundaries"][id]) {
    data["boundaries"][id] = {"name": boundary}
  }

  return id
}

function addComponent(id, component) {
  if (id == "") {
    id = toId(component)
  }

  if (component == "") {
    return ""
  }

  if (! data["components"][id]) {
    data["components"][id] = {"name": component}
  }

  return id
}

function addThreat(id, threat) {
  if (id == "") {
    id = toId(threat)
  }

  if (threat == "") {
    return ""
  }

  if (! data["threats"][id]) {
    data["threats"][id] = {"name": threat}
  }

  return id
}

function splitReferences(references) {
  if (references) {
    return references.split(",")
  } else {
    return []
  }
}

function addAlias(line) {
  var m = aliasPattern.exec(line)
  var klass = m[1].toLowerCase()
  var alias = m[2]
  var text = m[3]

  var id = toId(alias)

  switch (klass) {
    case "boundary":
      addBoundary(id, text)
      break;
    case "component":
      addComponent(id, text)
      break;
    case "threat":
      addThreat(id, text)
      break;
  }
}

function moreText(lines, index) {
  var nextLines = ""
  var references = []

  for (var j = index+1; j < lines.length; j++) {
    var nextLine = lines[j]
    var n = morePattern.exec(nextLine)
    if (n) {
      var nextText = n[1]
      var nextRef = n[2]
      var nextMore = n[3]

      nextLines += nextText
      index = j

      if (nextRef) {
        references = splitReferences(nextRef)
      }

      if (!nextMore) {
        break
      }
    } else {
      break
    }
  }

  return [nextLines, index, references]
}

function addDescription(lines, index) {
  var line = lines[index]
  var m = describePattern.exec(line)
  if (m) {
    var klass = m[1].toLowerCase()
    var id = m[2]
    var text = m[3]
    var more = m[4]

    var key = keyLookup[klass]

    data[key][id]["description"] = text
    if (more == '\\') {
      var nextLines = moreText(lines, index)
      data[key][id]["description"] += nextLines[0]
      return nextLines[1]
    } else {
      return index
    }
  } else {
    console.log("problem parsing description")
  }
}

function addMitigation(lines, index, meta) {
  var line = lines[index]
  var m = mitigationPattern.exec(line)

  if (m) {
    var boundary = m[1]
    var component = m[2]
    var threat = m[3]
    var mitigation = m[4]
    var references = splitReferences(m[5])
    var more = m[6]

    var boundaryId = addBoundary("",boundary)
    var componentId = addComponent("",component)
    var threatId = addThreat("",threat)

    var returnIndex = index

    if (more == '\\') {
      var nextLines = moreText(lines, index)
      mitigation += nextLines[0]
      references = references.concat(nextLines[2])
      returnIndex = nextLines[1]
    }

    var id = toId(mitigation)

    if (! data["projects"][project]["mitigations"][id]) {
      data["projects"][project]["mitigations"][id] = []
    }

    data["projects"][project]["mitigations"][id].push({
      "boundary": boundaryId,
      "component": componentId,
      "threat": threatId,
      "mitigation": mitigation,
      "references": references,
      "source": {
        "file": meta["file"],
        "line": meta["line"],
        "function": meta["name"]
      }
    })

    return returnIndex
  } else {
    console.log("something went wrong parsing mitigation")
  }
}

function addExposure(lines, index, meta) {
  var line = lines[index]
  var m = exposurePattern.exec(line)

  if (m) {
    var boundary = m[1]
    var component = m[2]
    var threat = m[3]
    var exposure = m[4]
    var references = splitReferences(m[5])
    var more = m[6]

    var boundaryId = addBoundary("",boundary)
    var componentId = addComponent("",component)
    var threatId = addThreat("",threat)

    var returnIndex = index

    if (more == '\\') {
      var nextLines = moreText(lines, index)
      exposure += nextLines[0]
      references = references.concat(nextLines[2])
      returnIndex = nextLines[1]
    }

    var id = toId(exposure)

    if (! data["projects"][project]["exposures"][id]) {
     data["projects"][project]["exposures"][id] = []
    }

    data["projects"][project]["exposures"][id].push({
      "boundary": boundaryId,
      "component": componentId,
      "threat": threatId,
      "exposure": exposure,
      "references": references,
      "source": {
        "file": meta["file"],
        "line": meta["line"],
        "function": meta["name"]
      }
    })

    return returnIndex
  } else {
    console.log("problem parsing exposure")
  }
}

function addTransfer(lines, index, meta) {
  var line = lines[index]
  var m = transferPattern.exec(line)

  if (m) {
    var threat = m[1]
    var boundary = m[2]
    var component = m[3]
    var transfer = m[4]
    var references = splitReferences(m[5])
    var more = m[6]

    var boundaryId = addBoundary("",boundary)
    var componentId = addComponent("",component)
    var threatId = addThreat("",threat)

    var returnIndex = index

    if (more == '\\') {
      var nextLines = moreText(lines, index)
      transfer += nextLines[0]
      references = references.concat(nextLines[2])
      returnIndex = nextLines[1]
    }

    var id = toId(transfer)

    if (! data["projects"][project]["transfers"][id]) {
     data["projects"][project]["transfers"][id] = []
    }

    data["projects"][project]["transfers"][id].push({
      "boundary": boundaryId,
      "component": componentId,
      "threat": threatId,
      "transfer": transfer,
      "references": references,
      "source": {
        "file": meta["file"],
        "line": meta["line"],
        "function": meta["name"]
      }
    })

    return returnIndex
  } else {
    console.log("problem parsing transfer")
  }
}

function addAcceptance(lines, index, meta) {
  var line = lines[index]
  var m = acceptancePattern.exec(line)

  if (m) {
    var threat = m[1]
    var boundary = m[2]
    var component = m[3]
    var acceptance = m[4]
    var references = splitReferences(m[5])
    var more = m[6]

    var boundaryId = addBoundary("",boundary)
    var componentId = addComponent("",component)
    var threatId = addThreat("",threat)

    var returnIndex = index

    if (more == '\\') {
      var nextLines = moreText(lines, index)
      acceptance += nextLines[0]
      references = references.concat(nextLines[2])
      returnIndex = nextLines[1]
    }

    var id = toId(acceptance)

    if (! data["projects"][project]["acceptances"][id]) {
     data["projects"][project]["acceptances"][id] = []
    }

    data["projects"][project]["acceptances"][id].push({
      "boundary": boundaryId,
      "component": componentId,
      "threat": threatId,
      "acceptance": acceptance,
      "references": references,
      "source": {
        "file": meta["file"],
        "line": meta["line"],
        "function": meta["name"]
      }
    })

    return returnIndex
  } else {
    console.log("problem parsing acceptance")
  }
}

// from http://stackoverflow.com/questions/171251/how-can-i-merge-properties-of-two-javascript-objects-dynamically
var merge = function() {
    var obj = {},
        i = 0,
        il = arguments.length,
        key;
    for (; i < il; i++) {
        for (key in arguments[i]) {
            if (arguments[i].hasOwnProperty(key)) {
                obj[key] = arguments[i][key];
            }
        }
    }
    return obj;
};

function findComments(data, found) {
  if (! data) {
    console.log("no data")
    return
  }
  if (data["leadingComments"]) {
    comment = {}
    comment["file"] = "meh.txt"
    comment["type"] = data["type"]
    comment["line"] = data["loc"]["start"]["line"]
    if (data["key"] && data["key"]["name"]) {
      comment["name"] = data["key"]["name"]
    }
    comment["comments"] = []
    for (var i = 0; i < data["leadingComments"].length; i++) {
      comment["comments"].push(data["leadingComments"][i]["value"])
    }
    found.push(comment)

  }

  if (data["trailingComments"]) {
    for (var i = 0; i < data["trailingComments"].length; i++) {
      found.push(data["trailingComments"][i]["value"])
    }
  } 
  
  if (data["body"]) {
    if (data["body"].constructor === Array) {
      for (var i = 0; i < data["body"].length; i++) {
        findComments(data["body"][i], found)
      }
    } else {
      findComments(data["body"], found)
    }
  } 
}

function parseLines(lines) {
  for (var k = 0; k < lines.length; k++) {
    var line = lines[k]
    m = tagPattern.exec(line)
    if (m) {
      switch(m[1].toLowerCase()) {
        case "mitigates":
          k = addMitigation(lines, k, comment)
          break;
        case "exposes":
          k = addExposure(lines, k, comment)
          break;
        case "transfers":
          k = addTransfer(lines, k, comment)
          break;
        case "accepts":
          k = addAcceptance(lines, k, comment)
          break;
        case "alias":
          addAlias(line)
          break;
        case "describe":
          k = addDescription(lines, k)
          break;
      }
    }
  }
}

function parseSource(src) {
  var parsed = esprima.parse(src, {loc:true, attachComment:true});

  var comments = []
  findComments(parsed, comments)
  for (var i = 0; i < comments.length; i++) {
    var comment = comments[i]
    for (var j = 0; j < comment["comments"].length; j++) {
      parseLines(comment["comments"][j].split("\n"))
    }  
  }
}

function parseSpec(src) {
  console.log(src)
  var lines = src.split("\n")
  for (var j = 0; j < lines.length; j++) {
    var line = lines[j]
    var m = globalPattern.exec(line)
    if (m) {
      switch(m[1].toLowerCase()) {
        case "alias":
          addAlias(line)
          break;
      } 
    }
  }
  parseLines(lines)
}

function parseJson(src) {
  data = merge(data, JSON.parse(src));
  console.log(JSON.stringify(data, null, 2))
}

exports.resetData = function() {
  resetData()
};

exports.parseSource = function(src) {
    parseSource(src)
};

exports.parseJson = function(src) {
    parseJson(src)
};

exports.parseSpec = function(src) {
    parseSpec(src)
};

exports.data = function() {
  return data
};

