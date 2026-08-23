package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

type integrityReadCloser struct{reader io.ReadCloser;hasher hash.Hash;expectedDigest string;expectedSize uint64;read uint64;verified bool;failure error}
func newIntegrityReadCloser(reader io.ReadCloser,digestValue string,size uint64)*integrityReadCloser{result:=&integrityReadCloser{reader:reader,hasher:sha256.New(),expectedDigest:digestValue,expectedSize:size};if size==0{result.verified=hex.EncodeToString(result.hasher.Sum(nil))==digestValue};return result}
func (reader *integrityReadCloser)Read(buffer []byte)(int,error){if reader.failure!=nil{return 0,reader.failure};if reader.read>=reader.expectedSize{return 0,io.EOF};maximum:=reader.expectedSize-reader.read;if uint64(len(buffer))>maximum{buffer=buffer[:maximum]};count,err:=reader.reader.Read(buffer);if count>0{reader.read+=uint64(count);_,_=reader.hasher.Write(buffer[:count]);if reader.read==reader.expectedSize{reader.verified=hex.EncodeToString(reader.hasher.Sum(nil))==reader.expectedDigest;if !reader.verified{reader.failure=ErrIntegrity;return count,reader.failure}}};if err==io.EOF&&reader.read<reader.expectedSize{reader.failure=ErrIntegrity;return count,reader.failure};return count,err}
func (reader *integrityReadCloser)Close()error{closeErr:=reader.reader.Close();if reader.failure!=nil{return errors.Join(reader.failure,closeErr)};if reader.read!=reader.expectedSize||!reader.verified{return errors.Join(ErrIntegrity,closeErr)};return closeErr}
