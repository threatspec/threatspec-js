var exports = module.exports = {};

var esprima = require('esprima');

// JSON Schema validation
var tv4 = require('tv4');

// Writing JSON file to file system
var fs = require('fs');

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

var idCleanPattern = /[^a-zA-Z0-9 ]+/g
var idSpacePattern = /\s+/g
var globalPattern = /^(?:[\s\*]*)@(alias)/i
var aliasPattern = /^(?:[\s\*]*)@alias (boundary|component|threat) (\@[a-z0-9_]+?) to (.+?)\s*$/i
var tagPattern = /^(?:[\s\*]*)@(mitigates|exposes|transfers|accepts)/i
var mitigationPattern = /^(?:[\s\*]*)@mitigates (.+?):(.+?) against (.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i
var exposurePattern = /^(?:[\s\*]*)@exposes (.+?):(.+?) to (.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i
var transferPattern = /^(?:[\s\*]*)@transfers (.+?) to (.+?):(.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i
var acceptancePattern = /^(?:[\s\*]*)@accepts (.+?) to (.+?):(.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i

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


function addAlias(line) {
  var m = aliasPattern.exec(line)
  var klass = m[1]
  var alias = m[2]
  var text = m[3]

  var id = toId(alias)

  switch (klass.toLowerCase()) {
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


function addMitigation(line, meta) {
  var m = mitigationPattern.exec(line)
  var boundary = m[1]
  var component = m[2]
  var threat = m[3]
  var mitigation = m[4]
  var reference = m[5]

  var id = toId(mitigation)

  var boundaryId = addBoundary("",boundary)
  var componentId = addComponent("",component)
  var threatId = addThreat("",threat)

  if (! data["projects"][project]["mitigations"][id]) {
    data["projects"][project]["mitigations"][id] = []
  }

  data["projects"][project]["mitigations"][id].push({
    "boundary": boundaryId,
    "component": componentId,
    "threat": threatId,
    "mitigation": mitigation,
    "source": {
      "file": meta["file"],
      "line": meta["line"],
      "function": meta["name"]
    }
  })
}

function addExposure(line, meta) {
  var m = exposurePattern.exec(line)
  var boundary = m[1]
  var component = m[2]
  var threat = m[3]
  var exposure = m[4]
  var reference = m[5]

  var id = toId(exposure)

  var boundaryId = addBoundary("",boundary)
  var componentId = addComponent("",component)
  var threatId = addThreat("",threat)

  if (! data["projects"][project]["exposures"][id]) {
   data["projects"][project]["exposures"][id] = []
  }

  data["projects"][project]["exposures"][id].push({
    "boundary": boundaryId,
    "component": componentId,
    "threat": threatId,
    "exposure": exposure,
    "source": {
      "file": meta["file"],
      "line": meta["line"],
      "function": meta["name"]
    }
  })
}

function addTransfer(line, meta) {
  var m = transferPattern.exec(line)
  var threat = m[1]
  var boundary = m[2]
  var component = m[3]
  var transfer = m[4]
  var reference = m[5]

  var id = toId(transfer)

  var boundaryId = addBoundary("",boundary)
  var componentId = addComponent("",component)
  var threatId = addThreat("",threat)

  if (! data["projects"][project]["transfers"][id]) {
   data["projects"][project]["transfers"][id] = []
  }

  data["projects"][project]["transfers"][id].push({
    "boundary": boundaryId,
    "component": componentId,
    "threat": threatId,
    "transfer": transfer,
    "source": {
      "file": meta["file"],
      "line": meta["line"],
      "function": meta["name"]
    }
  })
}

function addAcceptance(line, meta) {
  var m = acceptancePattern.exec(line)
  var threat = m[1]
  var boundary = m[2]
  var component = m[3]
  var acceptance = m[4]
  var reference = m[5]

  var id = toId(acceptance)

  var boundaryId = addBoundary("",boundary)
  var componentId = addComponent("",component)
  var threatId = addThreat("",threat)

  if (! data["projects"][project]["acceptances"][id]) {
   data["projects"][project]["acceptances"][id] = []
  }

  data["projects"][project]["acceptances"][id].push({
    "boundary": boundaryId,
    "component": componentId,
    "threat": threatId,
    "acceptance": acceptance,
    "source": {
      "file": meta["file"],
      "line": meta["line"],
      "function": meta["name"]
    }
  })
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

//console.log(JSON.stringify(esprima.parse(test, {loc:true,attachComment:true}), null, 4));

//console.log(JSON.stringify(parsed, null, 2))
//console.log("*************************************************")

function findComments(data, found) {
  //console.log("*************************************************")
  //console.log(JSON.stringify(data, null, 2))
  //console.log("*************************************************")
  if (! data) {
    return
  }
  if (data["leadingComments"]) {
    //console.log("found a leading coment")
    //console.log(JSON.stringify(data, null, 2))
    comment = {}
    comment["file"] = "meh.txt"
    comment["type"] = data["type"]
    comment["line"] = data["loc"]["start"]["line"]
    comment["name"] = data["key"]["name"]
    comment["comments"] = []
    for (var i = 0; i < data["leadingComments"].length; i++) {
      comment["comments"].push(data["leadingComments"][i]["value"])
    }
    found.push(comment)
  } else if (data["trailingComments"]) {
    console.log("found a trailing comment")
    for (var i = 0; i < data["trailingComments"].length; i++) {
      found.push(data["trailingComments"][i]["value"])
    }
  } else if (data["body"]) {
    console.log("found a body of type " + data["type"])
    if (data["body"].constructor === Array) {
      console.log("body is an array")
      for (var i = 0; i < data["body"].length; i++) {
        console.log("looking in body "+i)
        findComments(data["body"][i], found)
      }
    } else {
      findComments(data["body"], found)
    }
  } else {
    console.log("found nothing interesting")
  }
}

//console.log(JSON.stringify(data, null, 2))

function parseLines(lines) {
  for (var k = 0; k < lines.length; k++) {
    var line = lines[k]
    var m = tagPattern.exec(line)
    if (m) {
      console.log("found threatspec line "+line)
      switch(m[1].toLowerCase()) {
        case "mitigates":
          addMitigation(line, comment)
          break;
        case "exposes":
          addExposure(line, comment)
          break;
        case "transfers":
           addTransfer(line, comment)
          break;
        case "accepts":
            addAcceptance(line, comment)
          break;
      }
    }
  }
}

function parseSource(src) {
  var parsed = esprima.parse(src, {loc:true, attachComment:true});

  for (var i = 0; i < parsed["comments"].length; i++) {
    var lines = parsed["comments"][i]["value"].split("\n")
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
  }

  var comments = []
  findComments(parsed, comments)
  //console.log(JSON.stringify(comments, null, 2))
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

