const express = require("express");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const escapeHtml = require("escape-html");
const app = express();

app.get("/sqli", (req, res) => {
  db.query("SELECT * FROM u WHERE n = '" + req.query.name + "'");   // VULN sqli
  db.query("SELECT * FROM u WHERE n = ?", [req.query.name]);        // SAFE
});
app.get("/cmd", (req, res) => {
  cp.exec("ping " + req.body.host);                                  // VULN cmdi
  cp.execFile("ping", ["-c1", req.body.host]);                       // SAFE (arg, not command)
});
app.get("/file", (req, res) => {
  fs.readFileSync(path.join("/data", req.params.f));                 // VULN path
  fs.readFileSync(path.join("/data", path.basename(req.params.f)));  // SAFE
});
app.get("/xss", (req, res) => {
  res.send("<b>" + req.query.q + "</b>");                            // VULN xss
});
app.get("/xss2", (req, res) => {
  res.send("<b>" + escapeHtml(req.query.q) + "</b>");                // SAFE
});
app.get("/code", (req, res) => { eval(req.query.code); });           // VULN code
app.get("/ssrf", async (req, res) => { await axios.get(req.query.url); });  // VULN ssrf

module.exports.clone = function (url, dir) {
  cp.execSync(`git clone ${url} ${dir}`);                            // VULN lib cmdi
};
module.exports.get = function (obj, p) {
  return new Function("o", "return o." + p)(obj);                    // VULN lib code
};
