package providers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func signS3Request(request *http.Request,target S3Target,credentials S3Credentials,payloadDigest string,now time.Time)error{if request==nil||request.URL==nil||credentials.Validate(now)!=nil||!digest(payloadDigest){return ErrCredential};timestamp:=now.UTC().Format("20060102T150405Z");date:=now.UTC().Format("20060102");request.Header.Set("X-Amz-Date",timestamp);request.Header.Set("X-Amz-Content-Sha256",payloadDigest);if credentials.SessionToken!=""{request.Header.Set("X-Amz-Security-Token",credentials.SessionToken)};canonicalHeaders,signedHeaders:=canonicalS3Headers(request);canonicalRequest:=request.Method+"\n"+canonicalS3URI(request.URL)+"\n"+canonicalS3Query(request.URL.Query())+"\n"+canonicalHeaders+"\n"+signedHeaders+"\n"+payloadDigest;request.URL.RawQuery=canonicalS3Query(request.URL.Query());scope:=date+"/"+target.Region+"/s3/aws4_request";requestHash:=sha256.Sum256([]byte(canonicalRequest));stringToSign:="AWS4-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(requestHash[:]);dateKey:=hmacSHA256([]byte("AWS4"+credentials.SecretAccessKey),date);regionKey:=hmacSHA256(dateKey,target.Region);serviceKey:=hmacSHA256(regionKey,"s3");signingKey:=hmacSHA256(serviceKey,"aws4_request");signature:=hex.EncodeToString(hmacSHA256(signingKey,stringToSign));request.Header.Set("Authorization","AWS4-HMAC-SHA256 Credential="+credentials.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature);return nil}
func canonicalS3Headers(request *http.Request)(string,string){headers:=map[string]string{"host":request.URL.Host};for name,values:=range request.Header{lower:=strings.ToLower(name);if lower=="authorization"{continue};if strings.HasPrefix(lower,"x-amz-")||lower=="content-md5"||lower=="content-type"||lower=="if-match"||lower=="if-none-match"{normalized:=make([]string,0,len(values));for _,value:=range values{normalized=append(normalized,strings.Join(strings.Fields(value)," "))};headers[lower]=strings.Join(normalized,",")}};names:=make([]string,0,len(headers));for name:=range headers{names=append(names,name)};sort.Strings(names);var canonical strings.Builder;for _,name:=range names{canonical.WriteString(name);canonical.WriteByte(':');canonical.WriteString(headers[name]);canonical.WriteByte('\n')};return canonical.String(),strings.Join(names,";")}
func canonicalS3URI(value *url.URL)string{escaped:=value.EscapedPath();if escaped==""{return "/"};return strings.ReplaceAll(escaped,"+","%20")}
func canonicalS3Query(values url.Values)string{type pair struct{key,value string};pairs:=[]pair{};for key,items:=range values{if len(items)==0{pairs=append(pairs,pair{awsEscape(key),""});continue};for _,item:=range items{pairs=append(pairs,pair{awsEscape(key),awsEscape(item)})}};sort.Slice(pairs,func(i,j int)bool{if pairs[i].key==pairs[j].key{return pairs[i].value<pairs[j].value};return pairs[i].key<pairs[j].key});var result strings.Builder;for index,item:=range pairs{if index>0{result.WriteByte('&')};result.WriteString(item.key);result.WriteByte('=');result.WriteString(item.value)};return result.String()}
func awsEscape(value string)string{escaped:=url.QueryEscape(value);escaped=strings.ReplaceAll(escaped,"+","%20");escaped=strings.ReplaceAll(escaped,"%7E","~");return escaped}
func hmacSHA256(key []byte,value string)[]byte{mac:=hmac.New(sha256.New,key);_,_=mac.Write([]byte(value));return mac.Sum(nil)}
