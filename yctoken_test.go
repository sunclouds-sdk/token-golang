package yctoken

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"fmt"
)

func TestYCToken(t *testing.T) {

	yt :=NewYCToken(12345,"13212",46)
	assert.NotNil(t,yt)
	assert.Equal(t,int32(12345),yt.AppId)
	assert.Equal(t,"13212",yt.Uid)
	assert.Equal(t,int32(46),yt.ValidTime)

	yt.SetParameter("pkey1","pval1")
	yt.SetParameter("pkey2","pval2")
	assert.Equal(t,2,len(yt.Parameters))

	yt.SetPrivilege("pri1",1)
	yt.SetPrivilege("pri2",2)
	assert.Equal(t,2,len(yt.Privileges))

	token:=yt.BuildToken("appkey1234")

	fmt.Println("get token",token)

	goodyt,err:=ParseToken(token,"appkey1234")
	fmt.Println("get  YCToken",goodyt)
	assert.Nil(t,err)
	assert.Equal(t,int32(12345),goodyt.AppId)

	assert.Equal(t,"13212",goodyt.Uid)
	assert.Equal(t,"pval1",goodyt.Parameters["pkey1"])
	assert.Equal(t,"pval2",goodyt.Parameters["pkey2"])
	assert.Equal(t,int64(1),goodyt.Privileges["pri1"])
	assert.Equal(t,int64(2),goodyt.Privileges["pri2"])

	assert.Equal(t,true,goodyt.IsValid())

	_,err=ParseToken(token,"badkey1234")
	assert.NotNil(t,err)

	_,err = ParseToken(token[:len(token)-20],"appkey1234")
	require.NotNil(t,err)

	nyt,err:=ParseToken("AAAAeQAAAIsAAgQ6AAk1NDYxMjM1c3MAAwAD5L2gAAPlpb0ABTQ0MmNkAAhmZHNhZjU0NQADZmR5AAVzb2llNAADAAPkvaAAAAAcu--2pAAFNDQyY2QAAAAC39ir5AADZmR5AAAAAEmVB3QAAAFsCW-OfQACBBsgthakU7Z60NFpEQAibQYZPU0nqQ","2aeeb8de_3")
	require.Nil(t,err)
	fmt.Println("get  YCToken",nyt)

	assert.Equal(t,false,nyt.IsValid())

}

