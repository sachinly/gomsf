package msfrpc

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"gomsfrpc/utils"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"

	"github.com/vmihailenco/msgpack"
)

// MSFRPC is the entrypoint for MSFRPC connections
type MSFRPC struct {
	// Configuration
	Host     string
	Port     string
	URI      string
	Username string
	Password string
	Ssl      bool
	// Runtime
	isConnected bool
	authToken   string
}

type ConsoleReadResult struct {
	Data   string `msgpack:"data"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

type RetResult struct {
	Result string `msgpack:"result"`
}
type ConsoleInfo struct {
	Id     string
	Prompt string
	Busy   bool
}

type ModuleInfo struct {
	Type        string      `msgpack:"type"`
	Name        string      `msgpack:"name"`
	FullName    string      `msgpack:"fullname"`
	Rank        string      `msgpack:"rank"`
	Disclosure  string      `msgpack:"disclosuredate"`
	Description string      `msgpack:"description"`
	License     string      `msgpack:"license"`
	FilePath    string      `msgpack:"filepath"`
	Arch        []string    `msgpack:"arch"`
	Platform    []string    `msgpack:"platform"`
	Authors     []string    `msgpack:"authors"`
	Privileged  bool        `msgpack:"privileged"`
	References  [][]string  `msgpack:"references"`
	Stance      string      `msgpack:"stance"`
	Options     interface{} `msgpack:"options"`
}

type ModuleExecuteResult struct {
	JobID int    `msgpack:"job_id"`
	Uuid  string `msgpack:"uuid"`
}

type JobIdName struct {
	JobId   int
	JobName string
}

type DataStore struct {
	Payload                    string      `msgpack:"PAYLOAD"`
	WorkSpace                  interface{} `msgpack:"WORKSPACE"`
	Verbose                    interface{} `msgpack:"VERBOSE"`
	WfsDelay                   int         `msgpack:"WfsDelay"`
	EnableContextEncoding      bool        `msgpack:"EnableContextEncoding"`
	ContextInformationFile     interface{} `msgpack:"ContextInformationFile"`
	DisablePayloadHandler      bool        `msgpack:"DisablePayloadHandler"`
	Rhost                      string      `msgpack:"RHOST"`
	Rport                      int         `msgpack:"RPORT"`
	Chost                      string      `msgpack:"CHOST"`
	Cport                      int         `msgpack:"CPORT"`
	Lhost                      string      `msgpack:"LHOST"`
	Lport                      int         `msgpack:"LPORT"`
	Srhost                     string      `msgpack:"SRVHOST"`
	Srport                     int         `msgpack:"SRPORT"`
	Community                  string      `msgpack:"COMMUNITY"`
	Versin                     string      `msgpack:"VERSION"`
	TimeOut                    int         `msgpack:"TIMEOUT"`
	Retries                    int         `msgpack:"RETRIES"`
	SSL                        bool        `msgpack:"SSL"`
	SSLVersion                 string      `msppack:"SSLVersion"`
	SSLVerifyMode              string      `msgpack:"SSLVerifyMode"`
	CommandShellCleanupCommand string      `msgpack:"CommandShellCleanupCommand"`
	LoginCmd                   string      `msgpack:"LOGIN_CMD"`
	TargetId                   int         `msgpack:"TARGET"`
}

type JobInfo struct {
	JobId     int       `msgpack:"jid"`
	JobName   string    `msgpack:"name"`
	StartTime int64     `msgpack:"start_time"`
	UrlPath   string    `msgpack:"uripath"`
	Data      DataStore `msgpack:"datastore"`
}

type SessionInfo struct {
	SessionId   int    `msgpack:"sessionid"`
	Type        string `msgpack:"type"`
	TunnelLocal string `msgpack:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_payload"`
	Description string `msgpack:"desc"`
	Info        string `msgpack:"info"`
	Workspace   string `msgpack:"workspace"`
	SessionHost string `msgpack:"session_host"`
	SessionPort int    `msgpack:"session_port"`
	TargetHost  string `msgpack:"target_host"`
	UserName    string `msgpack:"username"`
	Uuid        string `msgpack:"uuid"`
	ExploitUuid string `msgpack:"exploit_uuid"`
	Routes      string `msgpack:"routes"`
	Arch        string `msgpack:"arch"`
}

////////////////////////////////////////////////////////////
// Constructor
////////////////////////////////////////////////////////////

// NewMsfrpc create a new MSFRPC object with specified parameters
func NewMsfrpc(host string, port string, uri string, username string, password string, ssl bool) *MSFRPC {
	msfrpc := MSFRPC{
		Host:     host,
		Port:     port,
		URI:      uri,
		Username: username,
		Password: password,
		Ssl:      ssl,
	}
	return &msfrpc
}

func encodeMsgpack(data interface{}) ([]byte, error) {
	return msgpack.Marshal(data)
}

func decodeMsgpack(bytes []byte, destination interface{}) {
	msgpack.Unmarshal(bytes, destination)
}

// safeString return a safe string for both meterpreter and classic command line
func safeString(input string) string {
	if regexp.MustCompile(`^[^:]+:\\$`).MatchString(input) {
		return input
	}
	return "\"" + input + "\""
}

////////////////////////////////////////////////////////////
// Remote calls
////////////////////////////////////////////////////////////

// CallAndUnmarshall call rpc method and unmarshal in data interface
func (msfrpc *MSFRPC) CallAndUnmarshall(method string, options []interface{}, data interface{}) error {
	stringBody, err := msfrpc.Call(method, options)
	if err != nil {
		return err
	}
	decodeMsgpack([]byte(stringBody), data)
	return nil
}

// Call call rpc method and return output
func (msfrpc *MSFRPC) Call(method string, options []interface{}) (string, error) {
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	requestData := []interface{}{method}
	if method != "auth.login" {
		requestData = append(requestData, msfrpc.authToken)
	}
	requestData = append(requestData, options...)
	//fmt.Println(requestData)
	requestBody, err := encodeMsgpack(requestData)
	if err != nil {
		return "", err
	}

	scheme := "http"
	if msfrpc.Ssl {
		scheme += "s"
	}
	request, err := http.NewRequest("POST", scheme+"://"+msfrpc.Host+":"+msfrpc.Port+msfrpc.URI, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "binary/message-pack")
	request.Header.Set("Accept", "binary/message-pack")
	request.Header.Set("Accept-Charset", "UTF-8")

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	rawBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	stringBody := fmt.Sprintf("%s", rawBody)

	return stringBody, nil
}

// Login login to rpc server
func (msfrpc *MSFRPC) AuthLogin() (string, error) {
	var result struct {
		Result     string `msgpack:"result"`
		Token      string `msgpack:"token"`
		Error      bool   `msgpack:"error"`
		ErrorClass string `msgpack:"error_class"`
		ErrorMsg   string `msgpack:"error_msg"`
	}
	err := msfrpc.CallAndUnmarshall("auth.login", []interface{}{msfrpc.Username, msfrpc.Password}, &result)

	if err != nil {
		return "", err
	}
	msfrpc.authToken = result.Token
	if result.Error == true {
		return result.ErrorMsg, errors.New("ErrorClass:" + result.ErrorClass + "\tErrormsg:" + result.ErrorMsg)
	}
	return "", nil
}

// Logout  to rpc server
func (msfrpc *MSFRPC) AuthLogout() error {
	var result RetResult
	err := msfrpc.CallAndUnmarshall("auth.logout", []interface{}{msfrpc.authToken}, &result)

	if err != nil {
		return err
	}
	return nil
}

/*
	console.create() create console success will return id
	param: 		null
	return: 	consoleid
*/
func (msfrpc *MSFRPC) ConsoleCreate() (string, error) {
	var result struct {
		Result    string `msgpack:"result"`
		Consoleid string `msgpack:"id"`
	}
	err := msfrpc.CallAndUnmarshall("console.create", []interface{}{}, &result)
	consoleid := result.Consoleid
	if err != nil {
		return "", err
	}
	return consoleid, nil
}

/*
	console.destroy destroy console by id
	param: consoleid
	return: success or failure
*/
func (msfrpc *MSFRPC) ConsoleDestroy(consoleid string) (string, error) {
	var result RetResult
	err := msfrpc.CallAndUnmarshall("console.destroy", []interface{}{consoleid}, &result)
	if err != nil {
		return "", err
	}
	Result := result.Result
	return Result, nil
}

/*
	console.list get console info list
	param: null
	return: ConsoleInfo list
*/
func (msfrpc *MSFRPC) ConsoleList() ([]ConsoleInfo, error) {

	var result map[string]interface{}
	err := msfrpc.CallAndUnmarshall("console.list", []interface{}{}, &result)
	if err != nil {
		return nil, err
	}
	var CStateLst []ConsoleInfo

	for _, v := range result {
		switch vv := v.(type) {
		case []interface{}:
			for _, u := range vv {
				var onecsinfo ConsoleInfo
				for key, value := range u.(map[string]interface{}) {
					strKey := fmt.Sprintf("%v", key)
					if strKey == "id" {
						onecsinfo.Id = fmt.Sprintf("%v", value)
					}
					if strKey == "prompt" {
						onecsinfo.Prompt = fmt.Sprintf("%s", string(value.([]byte)))
					}
					if strKey == "busy" {
						onecsinfo.Busy = value.(bool)
					}
				}
				CStateLst = append(CStateLst, onecsinfo)
			}

		}
	}
	return CStateLst, nil
}

/*
	console.write write command to console
	param:	consoleid,command
	return:	command's length, success or failure
*/
func (msfrpc *MSFRPC) ConsoleWrite(consoleid string, command string) (string, error) {
	var result RetResult
	err := msfrpc.CallAndUnmarshall("console.write", []interface{}{consoleid, command}, &result)
	Result := result.Result
	if err != nil {
		return "", err
	}
	return Result, nil
}

/*
	console.read read exec command's result
	param: consoleid
	return: data,prompt,busy
*/
func (msfrpc *MSFRPC) ConsoleRead(consoleid string) (crresult ConsoleReadResult) {
	var result ConsoleReadResult
	err := msfrpc.CallAndUnmarshall("console.read", []interface{}{consoleid}, &result)
	if err != nil {
		return
	}
	return
}

/*
	console.session_detach: simulates the user using the Control+Z shortcut to background an
	interactive session in the Metasploit Framework Console
	param: consoleid
	return: data,prompt,busy
*/
func (msfrpc *MSFRPC) ConsoleSessionDetach(consoleid string) (string, error) {
	var result RetResult
	err := msfrpc.CallAndUnmarshall("console.session_detach", []interface{}{consoleid}, &result)
	if err != nil {
		return "", err
	}
	Result := result.Result
	return Result, nil
}

/*
	console.session_kill: simulates the user using the Control+C shortcut to abort an interactive
	session in the Metasploit Framework Console
	param: consoleid
	return: success or failure
*/
func (msfrpc *MSFRPC) ConsoleSessionKill(consoleid string) (string, error) {
	var result RetResult
	err := msfrpc.CallAndUnmarshall("console.session_kill", []interface{}{consoleid}, &result)
	if err != nil {
		return "", err
	}
	Result := result.Result
	return Result, nil
}

/*
	console.session_kill: simulates the user hitting the tab key within the Metasploit Framework Console
	param: consoleid
	return: [option1,option2]
*/

func (msfrpc *MSFRPC) ConsoleTabs(consoleid string, cmdinput string) ([]string, error) {
	var result struct {
		Result []string `msgpack:"tabs"`
	}
	err := msfrpc.CallAndUnmarshall("console.tabs", []interface{}{consoleid, cmdinput}, &result)
	if err != nil {
		return nil, err
	}
	Result := result.Result
	return Result, nil
}

func (msfrpc *MSFRPC) ModulesList(moduleType string) ([]string, error) {
	var moduleTypelist = []string{"exploit", "auxiliary", "post", "payload", "encoder", "nop"}
	var result struct {
		Result []string `msgpack:"modules"`
	}
	isContain, _ := utils.Contain(moduleType, moduleTypelist)
	if isContain == false {
		moduleType = "exploit"
	}
	var method string = "module."
	if moduleType == "auxiliary" || moduleType == "post" {
		method = method + moduleType
	} else {
		method = method + moduleType + "s"
	}

	err := msfrpc.CallAndUnmarshall(method, []interface{}{}, &result)
	if err != nil {
		return nil, err
	}
	return result.Result, nil
}

func (msfrpc *MSFRPC) ModuleInfo(moduleType string, moduleName string) (moduleinfo ModuleInfo, err error) {
	var result ModuleInfo
	var moduleTypelist = []string{"exploit", "auxiliary", "post", "payload", "encoder", "nop"}
	isContain, _ := utils.Contain(moduleType, moduleTypelist)
	if isContain == false {
		moduleType = "exploit"
	}
	err = msfrpc.CallAndUnmarshall("module.info", []interface{}{moduleType, moduleName}, &result)
	if err != nil {
		return
	}
	moduleinfo = result
	return
}

func (msfrpc *MSFRPC) ModuleCompatiblePayloads(moduleName string) (payloadList []string, err error) {
	var result struct {
		Result []string `msgpack:"payloads"`
	}
	err = msfrpc.CallAndUnmarshall("module.compatible_payloads", []interface{}{moduleName}, &result)
	if err != nil {
		return
	}
	payloadList = result.Result
	return

}

func (msfrpc *MSFRPC) ModuleCompatibleSessions(moduleName string, targetid int) (payloadList []string, err error) {
	var result struct {
		Result []string `msgpack:"sessions"`
	}
	err = msfrpc.CallAndUnmarshall("module.compatible_payloads", []interface{}{moduleName, targetid}, &result)
	if err != nil {
		return
	}
	payloadList = result.Result
	return

}

func (msfrpc *MSFRPC) ModuleTargetCompatiblePayloads(moduleName string, targetid int) (payloadList []string, err error) {
	var result struct {
		Result []string `msgpack:"payloads"`
	}
	err = msfrpc.CallAndUnmarshall("module.compatible_payloads", []interface{}{moduleName, targetid}, &result)
	if err != nil {
		return
	}
	payloadList = result.Result
	return

}

func (msfrpc *MSFRPC) ModuleExecute(moduleName string, moduleType string, options map[string]interface{}) (moduleExecuteResult ModuleExecuteResult, err error) {
	var result ModuleExecuteResult
	err = msfrpc.CallAndUnmarshall("module.execute", []interface{}{moduleType, moduleName, options}, &result)
	if err != nil {
		return
	}
	moduleExecuteResult = result
	return
}

func (msfrpc *MSFRPC) JobList() (jobIdNameList []JobIdName, err error) {
	var result map[string]interface{}
	err = msfrpc.CallAndUnmarshall("job.list", []interface{}{}, &result)
	if err != nil {
		return
	}
	//var jobIdNameList []JobIdName
	for key, value := range result {
		var jobIdNameOne JobIdName
		jobIdNameOne.JobId, _ = strconv.Atoi(key)
		jobIdNameOne.JobName = fmt.Sprintf("%s", string(value.([]byte)))
		jobIdNameList = append(jobIdNameList, jobIdNameOne)
	}
	return
}

func (msfrpc *MSFRPC) JobInfo(jobid int) (jobinfo JobInfo, err error) {
	err = msfrpc.CallAndUnmarshall("job.info", []interface{}{jobid}, &jobinfo)
	if err != nil {
		return
	}
	return
}

func (msfrpc *MSFRPC) JobStop(jobid int) (string, error) {
	var result RetResult
	err := msfrpc.CallAndUnmarshall("job.stop", []interface{}{jobid}, &result)
	if err != nil {
		return "", err
	}
	return result.Result, nil
}

/*
	session list info : type=shell  		use session.shell_write or session.shell_read
						type=meterpreter	use session.meterpreter_write or session.meterpreter_read
*/
func (msfrpc *MSFRPC) SessionList() (sessionlst []SessionInfo, err error) {
	var result map[int]interface{}

	err = msfrpc.CallAndUnmarshall("session.list", []interface{}{}, &result)
	if err != nil {
		return sessionlst, err
	}
	for k, v := range result {
		var sessioninfo SessionInfo
		tmpdata, _ := msgpack.Marshal(v.(map[string]interface{}))
		msgpack.Unmarshal(tmpdata, &sessioninfo)
		sessioninfo.SessionId = int(k)
		sessionlst = append(sessionlst, sessioninfo)
	}
	return
}

func (msfrpc *MSFRPC) SessionStop(sessionid int) (string, error) {
	var result RetResult

	err := msfrpc.CallAndUnmarshall("session.stop", []interface{}{sessionid}, &result)
	if err != nil {
		return "", err
	}
	return result.Result, nil
}

func (msfrpc *MSFRPC) SessionShellWrite(sessionid int, command string) (int, error) {
	var result struct {
		Result int `msgpack:"write_count"`
	}

	err := msfrpc.CallAndUnmarshall("session.shell_write", []interface{}{sessionid, command}, &result)
	if err != nil {
		return 0, err
	}
	return result.Result, nil
}

func (msfrpc *MSFRPC) SessionShellRead(sessionid int) (string, error) {
	var result struct {
		Seq  int    `msgpack:"seq"`
		Data string `msgpack:"data"`
	}

	err := msfrpc.CallAndUnmarshall("session.shell_write", []interface{}{sessionid}, &result)
	if err != nil {
		return "", err
	}
	return result.Data, nil
}

func (msfrpc *MSFRPC) SessionMeterpreterWrite(sessionid int, command string) (string, error) {
	var result RetResult

	err := msfrpc.CallAndUnmarshall("session.meterpreter_write", []interface{}{sessionid, command}, &result)
	if err != nil {
		return "", err
	}
	return result.Result, nil
}

func (msfrpc *MSFRPC) SessionMeterpreterRead(sessionid int, command string) (string, error) {
	var result struct {
		Result string `msgpack:"data"`
	}
	err := msfrpc.CallAndUnmarshall("session.meterpreter_read", []interface{}{sessionid, command}, &result)
	if err != nil {
		return "", err
	}
	return result.Result, nil
}
