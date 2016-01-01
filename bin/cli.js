var commandLineArgs = require('command-line-args');
var fs = require('fs')
var ts = require('../lib/threatspec.js')

var cli = commandLineArgs([
  { name: 'project', alias: 'p', type: String, defaultValue: "default" },
  { name: 'out', alias: 'o', type: String, defaultValue: "threatspec.json" },
  { name: 'src', type: String, multiple: true, defaultOption: true, defaultValue: []}
])

var options = cli.parse()

ts.project = options["project"]
ts.resetData()

for (var i = 0; i < options["src"].length; i++) {
  var file = options["src"][i]
  var source = fs.readFileSync(file, 'utf8')
  switch(file.substr(file.lastIndexOf('.') + 1)) {
    case "js":
      ts.parseSource(source)
      break;
    case "json":
      ts.parseJson(source)
      break;
    case "threatspec":
      ts.parseSpec(source)
      break;
  }
}

fs.writeFile(options["out"], JSON.stringify(ts.data(), null, 2))
console.log("ThreatSpec written to "+options["out"])
