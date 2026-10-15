<?php
$conn = mysqli_connect("h", "u", "p", "d");
$name = $_GET['name'];
mysqli_query($conn, "SELECT * FROM u WHERE n = '" . $name . "'");              // VULN sqli
mysqli_query($conn, "SELECT * FROM u WHERE id = " . intval($_GET['id']));       // SAFE
system("ping " . $_POST['host']);                                             // VULN cmdi
system("ping " . escapeshellarg($_POST['host']));                             // SAFE
include("pages/" . $_GET['page'] . ".php");                                   // VULN path
readfile("files/" . basename($_GET['f']));                                    // SAFE
echo "<b>" . $_GET['q'] . "</b>";                                             // VULN xss
echo "<b>" . htmlspecialchars($_GET['q']) . "</b>";                           // SAFE
eval($_POST['code']);                                                         // VULN code
$data = unserialize($_COOKIE['prefs']);                                       // VULN deser
$ch = curl_init($_GET['url']);                                                // VULN ssrf
