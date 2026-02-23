local utils = require('utils')
local web = require('web')
local dm = require('dm')

local tostring = tostring

local csrf = _G["request"]["csrf"]
local param = csrf["csrf_param"]
local token = csrf["csrf_token"]

level,err,failcount,waitTime,first,wizard = web.login(data['UserName'], data['Password'], param..token)

local errcode,values = dm.GetParameterValues("InternetGatewayDevice.UserInterface.X_Web.UserInfo.{i}.",
    {
        "Username"
    }
);

if nil ~= data["SetFirst"] then
	for k, v in pairs(values) do
		if data['UserName'] == v["Username"] then
			print("find domain:"..k.."X_IsFirst")
			dm.SetParameterValues(k.."X_IsFirst", "1")
		end	
	end	
end

--4784229 4784230表示用户名,密码错误; 4784231表示3次登陆失败，等1min，4784232表示重复登陆 4784233表示用户过多
--这里的错误码与modal相互关联，对应的是webapi.h里面的错误码
if err == 4784229 or err == 4784230 then
	if failcount < 3 then
		utils.appenderror('errorCategory', "user_pass_err")--ATP_WEB_RET_INVALID_USERNAME --ATP_WEB_RET_INVALID_PASSWORD
	else
		if waitTime > 1 then
			utils.appenderror('waitTime', waitTime)
			utils.appenderror('errorCategory',  "Three_time_err_multi")--ATP_WEB_RET_LOGIN_WAIT
		else
			utils.appenderror('errorCategory',  "Three_time_err")--ATP_WEB_RET_LOGIN_WAIT
		end
	end
	utils.appenderror('count', failcount)
elseif err == 4784231 then
	if waitTime > 1 then
		utils.appenderror('waitTime', waitTime)
		utils.appenderror('errorCategory',  "Three_time_err_multi")--ATP_WEB_RET_LOGIN_WAIT
	else
		utils.appenderror('errorCategory',  "Three_time_err")--ATP_WEB_RET_LOGIN_WAIT
	end
	utils.appenderror('count', failcount)
elseif err == 4784232 then
	utils.appenderror('errorCategory',  "Duplicate_login") --ATP_WEB_RET_DUP_LOGIN
	utils.appenderror('count', failcount)
elseif err == 4784233 then
	utils.appenderror('errorCategory',  "Too_Many_user") --ATP_WEB_RET_TOO_MANY_USERS
	utils.appenderror('count', failcount)
else
	utils.appenderror('errorCategory',  "ok")	--correct
	utils.appenderror('IsFirst',  utils.toboolean(first))	--correct
	utils.appenderror('level',  level)	--correct
	utils.appenderror('IsWizard', utils.toboolean(wizard))
end

