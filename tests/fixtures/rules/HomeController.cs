using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller
{
    private readonly HttpClient http = new HttpClient();

    public IActionResult Sqli(string name)
    {
        var cmd = new SqlCommand("SELECT * FROM u WHERE n = '" + name + "'", conn);   // VULN sqli
        var safe = new SqlCommand("SELECT * FROM u WHERE n = @n", conn);              // SAFE
        return Ok();
    }

    public IActionResult Cmd([FromQuery] string host)
    {
        Process.Start("ping", host);                                                 // VULN cmdi
        return Ok();
    }

    public IActionResult Read(string f)
    {
        var a = System.IO.File.ReadAllText(Path.Combine("/data", f));               // VULN path
        var b = System.IO.File.ReadAllText(Path.Combine("/data", Path.GetFileName(f)));  // SAFE
        return Ok();
    }

    public IActionResult Xss()
    {
        var q = Request.Query["q"];
        return Content("<b>" + q + "</b>", "text/html");                            // VULN xss
    }

    public async Task<IActionResult> Ssrf(string url)
    {
        var s = await http.GetStringAsync(url);                                      // VULN ssrf
        return Ok(s);
    }
}
