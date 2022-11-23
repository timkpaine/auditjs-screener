#!/usr/bin/env node
const readline = require("readline");
const {Application} = require("auditjs/bin/Application/Application");
const {AuditOSSIndex} = require("auditjs/bin/Audit/AuditOSSIndex");

if (process.argv.length !== 3) {
  console.error("Usage: auditjs-min-score <score>");
  process.exit(1);
}

const maximum_security_score = parseInt(process.argv[2], 10);

// override auditor
AuditOSSIndex.prototype.auditResults = function(results) {
  const bad_libs = [];

  results.forEach((element) => {
    element.vulnerabilities.forEach((vuln) => {
      if (vuln.cvssScore > maximum_security_score) {
        bad_libs.push(element.coordinates);
      }
    });
  });

  // original behavior
  if (this.quiet) {
      results = results.filter((x) => {
          let _a;
          return x.vulnerabilities && ((_a = x.vulnerabilities) === null || _a === void 0 ? void 0 : _a.length) > 0;
      });
  }
  this.formatter.printAuditResults(results);

  // override default:
  // return Formatter_1.getNumberOfVulnerablePackagesFromResults(results) > 0;
  return bad_libs.length > 0;
}

let app = new Application();
let args = {ossi: true, json: true, quiet: true};
args._ = ["ossi", "-s"];
app.startApplication(args);
