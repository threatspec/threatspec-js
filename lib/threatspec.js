'use strict';

/**
 * @description ThreatSpec plugin for JSDoc
 * @module plugins/threatspec
 * @author Fraser Scott <fraser.scott@gmail.com>
 */

/* 
 * Things to do
 * parse existing json file
 * parse threatspec file
 */

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
var aliasPattern = /(boundary|component|threat) (\@[a-z0-9_]+?) to (.+?)\s*$/i
var mitigationPattern = /^(.+?):(.+?) against (.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i
var exposurePattern = /^(.+?):(.+?) to (.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i
var transferPattern = /^(.+?) to (.+?):(.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i
var acceptancePattern = /^(.+?) to (.+?):(.+?) with (.+?)\s*(?:\((.*?)\))?\s*$/i

if (env.opts.query["project"]) {
  var project = env.opts.query["project"]
} else {
  var project = project
}

if (env.opts.query["out"]) {
  var outFile = env.opts.query["out"]
} else {
  var outFile = "threatspec.json"
}

var data = {
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


function addAlias(tag, doclet) {
  var m = aliasPattern.exec(tag.value)
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

function addMitigation(tag, doclet) {
  var m = mitigationPattern.exec(tag.value)
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
      "file": doclet["meta"]["filename"],
      "line": doclet["meta"]["lineno"],
      "function": doclet["meta"]["code"]["name"]
    }
  })
}

function addExposure(tag, doclet) {
  var m = exposurePattern.exec(tag.value)
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
      "file": doclet["meta"]["filename"],
      "line": doclet["meta"]["lineno"],
      "function": doclet["meta"]["code"]["name"] // class?
    }
  })
}

function addTransfer(tag, doclet) {
  var m = transferPattern.exec(tag.value)
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
      "file": doclet["meta"]["filename"],
      "line": doclet["meta"]["lineno"],
      "function": doclet["meta"]["code"]["name"] // class?
    }
  })
}

function addAcceptance(tag, doclet) {
  var m = acceptancePattern.exec(tag.value)
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
      "file": doclet["meta"]["filename"],
      "line": doclet["meta"]["lineno"],
      "function": doclet["meta"]["code"]["name"] // class?
    }
  })
}

exports.handlers = {
    processingComplete: function(e) {
        if (tv4.validate(data, threatspecSchema)) {
          fs.writeFile(outFile, JSON.stringify(data, null, 2), function(err) {
            if(err) {
              return console.log(err);
            }
            console.log("ThreatSpec written to "+outFile);
          }); 
        } else {
          console.log("Validation failed")
          console.log(JSON.stringify(tv4.error, null, 2))
        }
    }
};

exports.defineTags = function(dictionary) {
  dictionary.defineTag('alias', {
      onTagged: function(doclet, tag) {
        if (doclet["meta"]["code"]["type"]) {
          addAlias(tag, doclet)
        }
      }
  });
  dictionary.defineTag('mitigates', {
      onTagged: function(doclet, tag) {
        if (doclet["meta"]["code"]["type"]) {
          addMitigation(tag, doclet)
        }
      }
  });
  dictionary.defineTag('exposes', {
      onTagged: function(doclet, tag) {
        if (doclet["meta"]["code"]["type"]) {
          addExposure(tag, doclet)
        }
      }
  });
  dictionary.defineTag('transfers', {
      onTagged: function(doclet, tag) {
        if (doclet["meta"]["code"]["type"]) {
          addTransfer(tag, doclet)
        }
      }
  });
  dictionary.defineTag('accepts', {
      onTagged: function(doclet, tag) {
        if (doclet["meta"]["code"]["type"]) {
          addAcceptance(tag, doclet)
        }
      }
  });
};
