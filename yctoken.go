package yctoken

import (
	"crypto/hmac"
	"crypto/sha1"
	"time"
	"bytes"
	"errors"
	"encoding/binary"
	"encoding/base64"
	"strings"
)

type YCToken struct {
	TokenVersion    int32                 // token版本字段
	TokenLen        int32                 // 整个token的字节长度
	AppId           int32                 // 项目ID
	Uid             string                // 在项目内唯一的用户ID
	Parameters      map[string]string     // 权限的参数
	Privileges      map[string]int64      // 各项权限对应的过期时间，UTC时间，单位毫秒
	BuildTimeStamp  int64                 // token的创建时间（UTC时间，单位毫秒）
	ValidTime       int32                 // token有效时长（单位秒）
	Signature       []byte                // 数字签名:hmac-sha1算法对digitalSignature前的所有数据运算得出，密钥使用appSecret
}

func hmac_sha1(key string,data []byte) []byte {

	mac := hmac.New(sha1.New, []byte(key))
	mac.Write(data)
	rbytes :=mac.Sum(nil)
	//fmt.Printf("%02x, %d \n", rbytes, len(rbytes))
	return rbytes
}
/*
NewYCToken 创建一个token 对象
	appid: 业务项目ID
	uid:  在项目内唯一的用户ID
	secs:  token过期的秒数，默认为30天
 */
func NewYCToken(appid int32 ,uid string,secs int32) *YCToken {

	if secs<=0 {
		secs = 30*24*3600
	}
	yt := &YCToken{
		TokenVersion: -10001001,
		TokenLen:0,
		AppId:appid,
		Uid:uid,
		Parameters:make(map[string]string),
		Privileges:make(map[string]int64),
		BuildTimeStamp:time.Now().UnixNano()/1000/1000,
		ValidTime:secs,
		Signature:nil,
	}
	return yt
}

func (yt * YCToken) SetValidSecs(secs int32) {
	yt.ValidTime = secs
}

func (yt * YCToken) SetParameter(pkey,pval string) {
	yt.Parameters[pkey] = pval
}

func (yt * YCToken) SetPrivilege(prkey string,exptime int64) {
	yt.Privileges[prkey] = exptime
}

func (yt * YCToken) IsValid() bool {
	if yt.BuildTimeStamp + int64( yt.ValidTime*1000)  > (time.Now().UnixNano()/1000/1000) {
		return true
	}
	return false
}

func (yt * YCToken) BuildToken(appkey string) string {

	yt.BuildTimeStamp = time.Now().UnixNano()/1000/1000

	buf := bytes.NewBuffer(make([]byte,0,1024))
	tdata:=make([]byte,12)
	binary.Write(buf,binary.BigEndian,yt.TokenVersion)
	binary.Write(buf,binary.BigEndian,yt.TokenLen)
	binary.Write(buf,binary.BigEndian,yt.AppId)

	binary.Write(buf,binary.BigEndian,uint16(len(yt.Uid)))
	binary.Write(buf,binary.BigEndian,[]byte(yt.Uid))

	binary.Write(buf,binary.BigEndian,uint16(len(yt.Parameters)))
	for k,v:=range yt.Parameters {
		binary.Write(buf,binary.BigEndian,uint16(len(k)))
		binary.Write(buf,binary.BigEndian,[]byte(k))
		binary.Write(buf,binary.BigEndian,uint16(len(v)))
		binary.Write(buf,binary.BigEndian,[]byte(v))
	}
	binary.Write(buf,binary.BigEndian,uint16(len(yt.Privileges)))
	for k,v:=range yt.Privileges {
		binary.Write(buf,binary.BigEndian,uint16(len(k)))
		binary.Write(buf,binary.BigEndian,[]byte(k))
		binary.Write(buf,binary.BigEndian,v)
	}
	binary.Write(buf,binary.BigEndian,yt.BuildTimeStamp)
	binary.Write(buf,binary.BigEndian,yt.ValidTime)

	tdata = buf.Bytes()

	// calculate the length again
	yt.TokenLen = int32(len(tdata))+20
	binary.BigEndian.PutUint32(tdata[4:8],uint32(yt.TokenLen))

	yt.Signature = hmac_sha1(appkey,tdata)
    token :=base64.URLEncoding.EncodeToString(append(tdata,yt.Signature...))
    token = strings.Replace(token,"=","",-1)  // 去掉结尾的=
	return  token
}

func ParseToken(token string,appkey string) (* YCToken,error) {
	yt := & YCToken{
		TokenVersion: 1,
		TokenLen:0,
		AppId:0,
		Uid:"",
		Parameters:make(map[string]string),
		Privileges:make(map[string]int64),
		BuildTimeStamp:0,
		ValidTime:0,
		Signature:make([]byte,20),
	}

	less :=len(token)%4
	if less >0 {
		// 补充尾部的=
		append :="===="
		token += append[0:4-less]
	}

	rdata,err:=base64.URLEncoding.DecodeString(token)
	if err!=nil {
		return yt,errors.New("urldecode err"+err.Error())
	}
	buf := bytes.NewBuffer(rdata)
	binary.Read(buf,binary.BigEndian,&yt.TokenVersion)
	binary.Read(buf,binary.BigEndian,&yt.TokenLen)
	binary.Read(buf,binary.BigEndian,&yt.AppId)

	ulen:=uint16(0)
	binary.Read(buf,binary.BigEndian,&ulen)
	uid:=make([]byte,ulen)
	binary.Read(buf,binary.BigEndian,&uid)
	yt.Uid = string(uid)

	// check length
	if yt.TokenLen != int32(len(rdata)) {
		return yt,errors.New("len err")
	}

	plen :=uint16(0)
	binary.Read(buf,binary.BigEndian,&plen)
	for i:=uint16(0);i<plen;i++ {
		klen,vlen:=uint16(0),uint16(0)

		binary.Read(buf,binary.BigEndian,&klen)
		k:=make([]byte,klen)
		binary.Read(buf,binary.BigEndian,k)

		binary.Read(buf,binary.BigEndian,&vlen)
		v:=make([]byte,vlen)
		binary.Read(buf,binary.BigEndian,v)

		yt.Parameters[string(k)] =string(v)
	}

	prlen :=uint16(0)
	binary.Read(buf,binary.BigEndian,&prlen)
	for i:=uint16(0);i<prlen;i++ {
		klen:=uint16(0)
		binary.Read(buf,binary.BigEndian,&klen)
		k:=make([]byte,klen)
		binary.Read(buf,binary.BigEndian,k)

		v:= int64(0)
		binary.Read(buf,binary.BigEndian,&v)
		yt.Privileges[string(k)] =v
	}
    binary.Read(buf,binary.BigEndian,&yt.BuildTimeStamp)
	binary.Read(buf,binary.BigEndian,&yt.ValidTime)
	binary.Read(buf,binary.BigEndian,yt.Signature)

	// check length
	sign := hmac_sha1(appkey,rdata[:yt.TokenLen-20])
	if !bytes.Equal(sign,yt.Signature) {
		return yt,errors.New("signature err")
	}

	return yt,nil
}

