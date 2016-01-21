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
          "boundary_desc": tsData["boundaries"][exposure["boundary"]]["description"],
          "component": tsData["components"][exposure["component"]]["name"],
          "component_desc": tsData["components"][exposure["component"]]["description"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["exposures"].push({
          "threat": tsData["threats"][exposure["threat"]]["name"],
          "threat_desc": tsData["threats"][exposure["threat"]]["description"],
          "exposure": exposure["exposure"],
          "ref": exposure["ref"],
          "function": exposure["source"]["function"],
          "file": "editor",
          "line": exposure["source"]["line"]
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
          "boundary_desc": tsData["boundaries"][mitigation["boundary"]]["description"],
          "component": tsData["components"][mitigation["component"]]["name"],
          "component_desc": tsData["components"][mitigation["component"]]["description"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["mitigations"].push({
          "threat": tsData["threats"][mitigation["threat"]]["name"],
          "threat_desc": tsData["threats"][mitigation["threat"]]["description"],
          "mitigation": mitigation["mitigation"],
          "ref": mitigation["ref"],
          "function": exposure["source"]["function"],
          "file": "editor",
          "line": exposure["source"]["line"]
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
          "boundary_desc": tsData["boundaries"][transfer["boundary"]]["description"],
          "component": tsData["components"][transfer["component"]]["name"],
          "component_desc": tsData["components"][transfer["component"]]["description"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["transfers"].push({
          "threat": tsData["threats"][transfer["threat"]]["name"],
          "threat_desc": tsData["threats"][transfer["threat"]]["description"],
          "transfer": transfer["transfer"],
          "ref": transfer["ref"],
          "function": exposure["source"]["function"],
          "file": "editor",
          "line": exposure["source"]["line"]
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
          "boundary_desc": tsData["boundaries"][acceptance["boundary"]]["description"],
          "component": tsData["components"][acceptance["component"]]["name"],
          "component_desc": tsData["components"][acceptance["component"]]["description"],
          "mitigations": [],
          "exposures": [],
          "transfers": [],
          "acceptances": []
        }

        components[component]["acceptances"].push({
          "threat": tsData["threats"][acceptance["threat"]]["name"],
          "threat_desc": tsData["threats"][acceptance["threat"]]["description"],
          "acceptance": acceptance["acceptance"],
          "ref": transfer["ref"],
          "function": exposure["source"]["function"],
          "file": "editor",
          "line": exposure["source"]["line"]
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

<p>{{boundary_desc}}
{{#component_desc}}
: {{component_desc}}
{{/component_desc}}
</p>

<ul class="list-unstyled">
  {{#exposures}}
  <li>
    <div class="threatspec exposure">exposed to {{threat}} by {{exposure}}</div>
    <div class="threatspec source">function {{function}} in {{file}} line {{line}}</div>
    {{#threat_desc}}
    <div class="threatspec desc">{{threat_desc}}</div>
    {{/threat_desc}}
  </li>
  {{/exposures}}
</ul>
<ul class="list-unstyled">
  {{#mitigations}}
  <li>
    <div class="threatspec mitigation">mitigates against {{threat}} with {{mitigation}}</div>
    <div class="threatspec source">function {{function}} in {{file}} line {{line}}</div>
    {{#threat_desc}}
    <div class="threatspec desc">{{threat_desc}}</div>
    {{/threat_desc}}
  </li>
  {{/mitigations}}
</ul>
<ul class="list-unstyled">
  {{#transfers}}
  <li>
    <div class="threatspec transfer">transfers {{threat}} with {{transfer}}</div>
    <div class="threatspec source">function {{function}} in {{file}} line {{line}}</div>
    {{#threat_desc}}
    <div class="threatspec desc">{{threat_desc}}</div>
    {{/threat_desc}}
  </li>
  {{/transfers}}
</ul>
<ul class="list-unstyled">
  {{#acceptances}}
  <li>
    <div class="threatspec acceptance">accepts {{threat}} with {{acceptance}}</div>
    <div class="threatspec source">function {{function}} in {{file}} line {{line}}</div>
    {{#threat_desc}}
    <div class="threatspec desc">{{threat_desc}}</div>
    {{/threat_desc}}
  </li>
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
