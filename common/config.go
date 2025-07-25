package common

var Userdict = map[string][]string{
	"ftp":        {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"mysql":      {"root", "mysql"},
	"mssql":      {"sa", "sql"},
	"smb":        {"administrator", "admin", "guest"},
	"rdp":        {"administrator", "admin", "guest"},
	"postgresql": {"postgres", "admin"},
	"ssh":        {"root", "admin", "mysql", "db2cat"},
	"mongodb":    {"root", "admin"},
	"oracle":     {"sys", "system", "admin", "oracle", "test", "web", "orcl"},
}

var Passwords = []string{"123456", "12345678", "admin", "admin123", "root", "",
	"mysql", "db2cat", "pass123", "pass@123", "password", "123123", "654321", "111111", "123", "1",
	"admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123",
	"{user}_123", "{user}#123", "{user}@111", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "{user}@2022", "{user}@2023", "{user}@2024",
	"Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe", "123qwe!@#", "123456789", "123321", "!QAZ@WSX",
	"666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "qwerty", "qwerty123", "qwertyuiop",
	"abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123",
	"Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!",
	"QWE123qwe", "A123456s!", "sa123456", "1q2w3e", "Charge123", "Aa123456789", "Huawei@123", "!QAZ2wsx#EDC", "1qaz@WSX3edc", "1qaz2wsx#EDC",
}

var PORTList = map[string]int{
	"ftp":         21,
	"ssh":         22,
	"findnet":     135,
	"netbiosUDP":  137,
	"netbios":     139,
	"smb":         445,
	"mssql":       1433,
	"oracle":      1521,
	"mysql":       3306,
	"rdp":         3389,
	"psql":        5432,
	"redis":       6379,
	"fcgi":        9000,
	"mem":         11211,
	"mgo":         27017,
	"ms17010":     1000001,
	"cve20200796": 1000002,
	"web":         1000003,
	"webonly":     1000003,
	"webpoc":      1000003,
	"smb2":        1000004,
	"wmiexec":     1000005,
	"all":         0,
	"portscan":    0,
	"icmp":        0,
	"main":        0,
}
var PortGroup = map[string]string{
	"ftp":         "21",
	"ssh":         "22",
	"findnet":     "135",
	"netbios":     "139",
	"smb":         "445",
	"mssql":       "1433",
	"oracle":      "1521",
	"mysql":       "3306",
	"rdp":         "3389",
	"psql":        "5432",
	"redis":       "6379",
	"fcgi":        "9000",
	"mem":         "11211",
	"mgo":         "27017",
	"ms17010":     "445",
	"cve20200796": "445",
	"service":     "21,22,135,139,445,1433,1521,3306,3389,5432,6379,9000,11211,27017",
	"db":          "1433,1521,3306,5432,6379,11211,27017",
	"web":         "80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880",
	"all":         "1-65535",
	"main":        "21,22,25,80,81,110,135,139,143,587,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017",
}
var IsSave = !TmpSave
var Outputfile = "result.txt"

var Webport = "80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880"
var DefaultPorts = "21,22,23,25,80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,110,135,139,143,389,443,444,445,465,636,1080,3128,1022,1024,1193，1433,1434,1521,1522,2222,2323,22222,3306,3307,3389,5432,5433,5900,6379,6380,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,8000,8001,8002,8443,8888,8080,8081,8085,8086,8089,9000,9999,10000,10443,10444,11211,27017"

type HostInfo struct {
	Host    string
	Ports   string
	Url     string
	Infostr []string
	Banner  string
}

type PocInfo struct {
	Target  string
	PocName string
}

var (
	Ports            string
	Path             string
	Scantype         string
	Command          string
	SshKey           string
	Domain           string
	Username         string
	Password         string
	Proxy            string
	TcpTimeout       int64
	WebTimeout       int64
	TmpSave          bool
	NoPing           bool
	Ping             bool
	Pocinfo          PocInfo
	NoPoc            bool
	NoBrute          bool
	RedisFile        string
	RedisShell       string
	Userfile         string
	Passfile         string
	HostFile         string
	PortFile         string
	PocPath          string
	PortScanThreads  int
	URL              string
	UrlFile          string
	Urls             []string
	NoPorts          string
	NoHosts          string
	SC               string
	PortAdd          string
	UserAdd          string
	PassAdd          string
	BruteThread      int
	LiveTop          int
	Socks5Proxy      string
	Hash             string
	Hashs            []string
	HashBytes        [][]byte
	HostPort         []string
	IsWmi            bool
	Noredistest      bool
	Iface            string  //own add
	PingRate         float64 //own add
	PingTimeout      int     //own add
	UseNmap          bool    //own add
	TitleScanThreads int     //own add
	IsScreenShot     bool    //own add
)

var (
	UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
	Accept        = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
	DnsLog        bool
	PocNum        int
	PocFull       bool
	CeyeDomain    string
	ApiKey        string
	Cookie        string
	Title_scan_ch chan int
)
