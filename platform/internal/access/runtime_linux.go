//go:build linux

package access

type LinuxAccessRuntime struct{
	Files *LinuxFileExecutor
	Credentials *LinuxCredentialExecutor
	Terminal *LinuxTerminalBroker
	Cron *LinuxCronExecutor
	Git *LinuxGitExecutor
	Staging *LinuxStagingExecutor
	Handler *AccessExecutorHandler
}

func NewLinuxAccessRuntime(resolver LinuxSiteResolver,secretSource *LinuxAccessSecretSource,controlGID uint32)(*LinuxAccessRuntime,error){
	files,err:=NewLinuxFileExecutor(resolver);if err!=nil{return nil,err}
	credentials,err:=NewLinuxCredentialExecutor(files);if err!=nil{return nil,err}
	terminal,err:=NewLinuxTerminalBroker(credentials,controlGID);if err!=nil{return nil,err}
	cron,err:=NewLinuxCronExecutor(files,secretSource);if err!=nil{return nil,err}
	git,err:=NewLinuxGitExecutor(files,secretSource);if err!=nil{return nil,err}
	staging,err:=NewLinuxStagingExecutor(files);if err!=nil{return nil,err}
	handler,err:=NewAccessExecutorHandler(AccessExecutorSet{Files:files,Credentials:credentials,Terminal:terminal,Cron:cron,Git:git,Staging:staging});if err!=nil{return nil,err}
	return &LinuxAccessRuntime{Files:files,Credentials:credentials,Terminal:terminal,Cron:cron,Git:git,Staging:staging,Handler:handler},nil
}
