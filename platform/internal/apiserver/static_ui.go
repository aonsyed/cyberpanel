package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const defaultMaximumUIBytes int64 = 512 << 20
const maximumUIAssetBytes int64 = 64 << 20
var fingerprintedAssetPattern=regexp.MustCompile(`(?i)[._-][0-9a-f]{8,64}[._-]`)

type staticAsset struct{content []byte;contentType string;etag string;modified time.Time}
type StaticUI struct{assets map[string]staticAsset;index staticAsset}

func LoadStaticUI(root string,maximumTotal int64)(*StaticUI,error){if !filepath.IsAbs(root)||filepath.Clean(root)!=root{return nil,invalid("UI dist root")};rootInfo,err:=os.Lstat(root);if err!=nil{return nil,err};if !rootInfo.IsDir()||rootInfo.Mode()&os.ModeSymlink!=0||rootInfo.Mode().Perm()&0002!=0{return nil,errors.New("unsafe UI dist root")};if maximumTotal<=0||maximumTotal>defaultMaximumUIBytes{maximumTotal=defaultMaximumUIBytes};ui:=&StaticUI{assets:map[string]staticAsset{}};var total int64;err=filepath.WalkDir(root,func(path string,entry os.DirEntry,walkErr error)error{if walkErr!=nil{return walkErr};if path==root{return nil};if entry.Type()&os.ModeSymlink!=0{return fmt.Errorf("UI dist contains a symbolic link: %s",path)};relative,err:=filepath.Rel(root,path);if err!=nil{return err};info,err:=entry.Info();if err!=nil{return err};if entry.IsDir(){if info.Mode().Perm()&0002!=0{return fmt.Errorf("unsafe UI directory: %s",relative)};if strings.HasPrefix(entry.Name(),"."){return filepath.SkipDir};return nil};if !info.Mode().IsRegular()||info.Mode().Perm()&0002!=0||info.Size()<0||info.Size()>maximumUIAssetBytes{return fmt.Errorf("unsafe UI asset: %s",relative)};total+=info.Size();if total>maximumTotal{return errors.New("UI dist exceeds configured memory bound")};file,err:=os.Open(path);if err!=nil{return err};opened,statErr:=file.Stat();if statErr!=nil||!os.SameFile(info,opened){_ = file.Close();return fmt.Errorf("UI asset changed while opening: %s",relative)};content,readErr:=io.ReadAll(io.LimitReader(file,maximumUIAssetBytes+1));closeErr:=file.Close();if readErr!=nil{return readErr};if closeErr!=nil{return closeErr};if int64(len(content))!=info.Size(){return fmt.Errorf("UI asset changed while reading: %s",relative)};route:="/"+filepath.ToSlash(relative);sum:=sha256.Sum256(content);contentType:=mime.TypeByExtension(filepath.Ext(relative));if contentType==""{contentType="application/octet-stream"};asset:=staticAsset{content:content,contentType:contentType,etag:`"`+hex.EncodeToString(sum[:])+`"`,modified:info.ModTime().UTC()};ui.assets[route]=asset;if route=="/index.html"{ui.index=asset};return nil});if err!=nil{return nil,err};if len(ui.index.content)==0{return nil,errors.New("UI dist has no index.html")};return ui,nil}

func(ui *StaticUI)ServeHTTP(writer http.ResponseWriter,request *http.Request){if ui==nil||(request.Method!=http.MethodGet&&request.Method!=http.MethodHead){writeProblem(writer,classifyError(ErrNotFound,request.Header.Get("X-Request-ID")),1<<20);return};if strings.HasPrefix(request.URL.Path,"/api/")||strings.HasPrefix(request.URL.Path,"/health/")||request.URL.RawQuery!=""&&len(request.URL.RawQuery)>4096{writeProblem(writer,classifyError(ErrNotFound,request.Header.Get("X-Request-ID")),1<<20);return};path:=request.URL.EscapedPath();if path==""{path="/"};lowerPath:=strings.ToLower(path);for _,segment:=range strings.Split(request.URL.Path,"/"){if segment=="."||segment==".."{writeProblem(writer,classifyError(ErrNotFound,request.Header.Get("X-Request-ID")),1<<20);return}};if strings.Contains(lowerPath,"%2f")||strings.Contains(lowerPath,"%5c")||strings.Contains(lowerPath,"%2e")||strings.Contains(path,"..")||strings.ContainsAny(path,"\x00\\"){writeProblem(writer,classifyError(ErrNotFound,request.Header.Get("X-Request-ID")),1<<20);return};asset,exists:=ui.assets[path];spa:=false;if !exists{accept:=request.Header.Get("Accept");last:=path[strings.LastIndex(path,"/")+1:];if strings.Contains(accept,"text/html")&&!strings.Contains(last,"."){asset=ui.index;exists=true;spa=true}};if !exists{writeProblem(writer,classifyError(ErrNotFound,request.Header.Get("X-Request-ID")),1<<20);return};writer.Header().Set("Content-Type",asset.contentType);writer.Header().Set("ETag",asset.etag);writer.Header().Set("Last-Modified",asset.modified.Format(http.TimeFormat));writer.Header().Set("Content-Security-Policy","default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'");writer.Header().Set("Cross-Origin-Opener-Policy","same-origin");writer.Header().Set("Cross-Origin-Resource-Policy","same-origin");if spa||path=="/"||path=="/index.html"{writer.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")}else if fingerprintedAssetPattern.MatchString(filepath.Base(path)){writer.Header().Set("Cache-Control","public, max-age=31536000, immutable")}else{writer.Header().Set("Cache-Control","public, max-age=300, must-revalidate")};if request.Header.Get("If-None-Match")==asset.etag{writer.WriteHeader(http.StatusNotModified);return};writer.Header().Set("Content-Length",fmt.Sprintf("%d",len(asset.content)));writer.WriteHeader(http.StatusOK);if request.Method==http.MethodGet{_,_=writer.Write(asset.content)}}
