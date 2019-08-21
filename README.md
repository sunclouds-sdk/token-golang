# token-golang
本文介绍了golang版YCToken SDK的使用方法，并提供了产YCToken和验YCToken的代码示例（最新版本v1.0.0）。

# 描述
YCToken能够支持身份验证和过期时间验证，并支持业务参数的透传（不对业务参数进行校验）。

# 示例代码
**产token** 
 
	appid:=int32(12345)
	uid:="1234444"
	expiresecs:=int32(46)
	yt :=yctoken.NewYCToken(appid,uid,expiresecs)
	// 设置业务参数
	yt.SetParameter("pkey1","pval1")
	yt.SetParameter("pkey2","pval2")
	// 设置业务权限
	yt.SetPrivilege("pri1",300)
	yt.SetPrivilege("pri2",400)
	// 生成token 串
	token:=yt.BuildToken("appkey1234")
 
 **验token** 
 
	// 解析token串，生成YCToken对象
 	yt,err:=yctoken.ParseToken(token,"appkey1234")
	if err!=nil {
		// print err
	} else {
		if yt.IsValid(){
			// token 有效
			// do something
			
		} else {
			// token 已过期
		}
	}
 
 
