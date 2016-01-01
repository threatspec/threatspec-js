var ts = require('./threatspec.js');
var mustache = require('mustache');

function parse() {
  ts.resetData();
  ts.parseSource(editor.getValue());
  var tsData = ts.data()

  document.getElementById('json-data').textContent = JSON.stringify(tsData, null, 2)

  var components = {}
  var reportData = {
    "specification": "", 
    "project": "",
    "components": []
  }
  var project = Object.keys(tsData["projects"])[0]

  reportData["specification"] = tsData["specification"]["name"]
  reportData["project"] = project

  if (tsData["projects"][project]["exposures"]) {
    for (id in tsData["projects"][project]["exposures"]) {
      for (var i = 0; i < tsData["projects"][project]["exposures"][id].length; i++) {
        var exposure = tsData["projects"][project]["exposures"][id][i]
        var component = exposure["boundary"] + ":" + exposure["component"]
        components[component] = components[component] || {
          "boundary": tsData["boundaries"][exposure["boundary"]]["name"],
          "component": tsData["components"][exposure["component"]]["name"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["exposures"].push({
          "threat": tsData["threats"][exposure["threat"]]["name"],
          "exposure": exposure["exposure"],
          "ref": exposure["ref"],
          "function": "abc",
          "file": "meh.js",
          "line": 666
        })

      }
    }

  }

  if (tsData["projects"][project]["mitigations"]) {
    for (id in tsData["projects"][project]["mitigations"]) {
      for (var i = 0; i < tsData["projects"][project]["mitigations"][id].length; i++) {
        var mitigation = tsData["projects"][project]["mitigations"][id][i]
        var component = mitigation["boundary"] + ":" + mitigation["component"]
        components[component] = components[component] || {
          "boundary": tsData["boundaries"][mitigation["boundary"]]["name"],
          "component": tsData["components"][mitigation["component"]]["name"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["mitigations"].push({
          "threat": tsData["threats"][mitigation["threat"]]["name"],
          "mitigation": mitigation["mitigation"],
          "ref": mitigation["ref"],
          "function": "abc",
          "file": "meh.js",
          "line": 666
        })

      }
    }
  }

  if (tsData["projects"][project]["transfers"]) {
    for (id in tsData["projects"][project]["transfers"]) {
      for (var i = 0; i < tsData["projects"][project]["transfers"][id].length; i++) {
        var transfer = tsData["projects"][project]["transfers"][id][i]
        var component = transfer["boundary"] + ":" + transfer["component"]
        components[component] = components[component] || {
          "boundary": tsData["boundaries"][transfer["boundary"]]["name"],
          "component": tsData["components"][transfer["component"]]["name"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["transfers"].push({
          "threat": tsData["threats"][transfer["threat"]]["name"],
          "transfer": transfer["transfer"],
          "ref": transfer["ref"],
          "function": "abc",
          "file": "meh.js",
          "line": 666
        })

      }
    }
  }

  if (tsData["projects"][project]["acceptances"]) {
    for (id in tsData["projects"][project]["acceptances"]) {
      for (var i = 0; i < tsData["projects"][project]["acceptances"][id].length; i++) {
        var acceptance = tsData["projects"][project]["acceptances"][id][i]
        var component = acceptance["boundary"] + ":" + acceptance["component"]
        components[component] = components[component] || {
          "boundary": tsData["boundaries"][acceptance["boundary"]]["name"],
          "component": tsData["components"][acceptance["component"]]["name"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["acceptances"].push({
          "threat": tsData["threats"][acceptance["threat"]]["name"],
          "acceptance": acceptance["acceptance"],
          "ref": transfer["ref"],
          "function": "abc",
          "file": "meh.js",
          "line": 666
        })

      }
    }
  }

  for (component in components) {
    reportData["components"].push(components[component])
  }

  var template = `
<h1 class="threatspec title">{{specification}} report for {{project}}</h1>
{{#components}}
<h2 class="threatspec component">{{boundary}} {{component}}</h2>
<ul class="list-unstyled">
  {{#exposures}}
  <li><span class="threatspec exposure">exposed to {{threat}} by {{exposure}}</span><br/><span class="threatspec source">{{function}} in {{file}}:{{line}}</span></li>
  {{/exposures}}
</ul>
<ul class="list-unstyled">
  {{#mitigations}}
  <li><span class="threatspec mitigation">mitigates against {{threat}} with {{mitigation}}</span><br/><span class="threatspec source">{{function}} in {{file}}:{{line}}</span></li>
  {{/mitigations}}
</ul>
<ul class="list-unstyled">
  {{#transfers}}
  <li><span class="threatspec transfer">transfers {{threat}} with {{transfer}}</span><br/><span class="threatspec source">{{function}} in {{file}}:{{line}}</span></li>
  {{/transfers}}
</ul>
<ul class="list-unstyled">
  {{#acceptances}}
  <li><span class="threatspec acceptance">accepts {{threat}} with {{acceptance}}</span><br/><span class="threatspec source">{{function}} in {{file}}:{{line}}</span></li>
  {{/acceptances}}
</ul>
{{/components}}
`

  var output = mustache.render(template, reportData);
  document.querySelector('#report').innerHTML = output;

}

var button = document.getElementById('parse');
button.addEventListener('click', parse);

parse();
