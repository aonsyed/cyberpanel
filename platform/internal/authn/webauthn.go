package authn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type WebAuthnEngine interface {
	RegistrationOptions(identity.ID,string,string,[]byte,bool)([]byte,error)
	FinishRegistration([]byte,[]byte,string,[]string,bool)(WebAuthnCredential,error)
	AssertionOptions(string,[]byte,[]WebAuthnCredential,bool)([]byte,error)
	VerifyAssertion([]byte,[]byte,string,[]string,bool,WebAuthnCredential)(uint32,error)
}

type WebAuthnCredential struct {
	PrincipalID identity.ID `json:"principal_id"`
	RPID string `json:"rp_id"`
	CredentialID string `json:"credential_id"`
	COSEKey string `json:"cose_key"`
	Algorithm int64 `json:"algorithm"`
	SignCount uint32 `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
}

type NativeWebAuthn struct{}

func (NativeWebAuthn) RegistrationOptions(principal identity.ID,rpID,display string,challenge []byte,requireUV bool)([]byte,error){
	if !principal.Valid()||!validRPID(rpID)||len(challenge)!=32{return nil,ErrInvalid}
	selection:=map[string]any{"residentKey":"preferred","requireResidentKey":false,"userVerification":"preferred"};if requireUV{selection["userVerification"]="required"}
	value:=map[string]any{"challenge":base64.RawURLEncoding.EncodeToString(challenge),"rp":map[string]string{"id":rpID,"name":display},"user":map[string]string{"id":base64.RawURLEncoding.EncodeToString([]byte(principal)),"name":principal.String(),"displayName":principal.String()},"pubKeyCredParams":[]map[string]any{{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},{"type":"public-key","alg":-257}},"timeout":300000,"attestation":"none","authenticatorSelection":selection}
	return json.Marshal(value)
}

func (NativeWebAuthn) AssertionOptions(rpID string,challenge []byte,credentials []WebAuthnCredential,requireUV bool)([]byte,error){
	if !validRPID(rpID)||len(challenge)!=32||len(credentials)==0||len(credentials)>256{return nil,ErrInvalid};allowed:=make([]map[string]any,0,len(credentials));for _,credential:=range credentials{if credential.RPID!=rpID{return nil,ErrInvalid};id,err:=base64.RawURLEncoding.DecodeString(credential.CredentialID);if err!=nil||len(id)<16||len(id)>1024{return nil,ErrInvalid};allowed=append(allowed,map[string]any{"type":"public-key","id":base64.RawURLEncoding.EncodeToString(id)})};verification:="preferred";if requireUV{verification="required"};return json.Marshal(map[string]any{"challenge":base64.RawURLEncoding.EncodeToString(challenge),"rpId":rpID,"allowCredentials":allowed,"userVerification":verification,"timeout":300000})
}

type registrationEnvelope struct{ID string `json:"id"`;Type string `json:"type"`;RawID string `json:"raw_id"`;Response struct{ClientDataJSON string `json:"client_data_json"`;AttestationObject string `json:"attestation_object"`;Transports []string `json:"transports,omitempty"`} `json:"response"`}
type assertionEnvelope struct{ID string `json:"id"`;Type string `json:"type"`;RawID string `json:"raw_id"`;Response struct{ClientDataJSON string `json:"client_data_json"`;AuthenticatorData string `json:"authenticator_data"`;Signature string `json:"signature"`;UserHandle *string `json:"user_handle"`} `json:"response"`}
type assertionRequestEnvelope struct{ChallengeID identity.ID `json:"challenge_id"`;Credential json.RawMessage `json:"credential"`}
type clientData struct{Type string `json:"type"`;Challenge string `json:"challenge"`;Origin string `json:"origin"`;CrossOrigin bool `json:"crossOrigin"`;TopOrigin string `json:"topOrigin,omitempty"`}

func (NativeWebAuthn) FinishRegistration(response,challenge []byte,rpID string,origins []string,requireUV bool)(WebAuthnCredential,error){
	var envelope registrationEnvelope;if decodeBrowserJSON(response,&envelope)!=nil||envelope.Type!="public-key"{return WebAuthnCredential{},ErrInvalid};rawID,clientRaw,attestation,err:=decodeRegistration(envelope);if err!=nil{return WebAuthnCredential{},err};if err=verifyClientData(clientRaw,"webauthn.create",challenge,rpID,origins);err!=nil{return WebAuthnCredential{},err};root,consumed,err:=parseCBOR(attestation,0);if err!=nil||consumed!=len(attestation){return WebAuthnCredential{},ErrInvalid};object,ok:=root.(map[any]any);if !ok{return WebAuthnCredential{},ErrInvalid};format,_:=object["fmt"].(string);if format!="none"{return WebAuthnCredential{},fmt.Errorf("%w: only privacy-preserving none attestation is accepted",ErrInvalid)};authData,ok:=object["authData"].([]byte);if !ok{return WebAuthnCredential{},ErrInvalid};parsed,err:=parseRegistrationAuthData(authData,rpID,requireUV);if err!=nil{return WebAuthnCredential{},err};if subtle.ConstantTimeCompare(rawID,parsed.credentialID)!=1{return WebAuthnCredential{},ErrInvalid};return WebAuthnCredential{RPID:rpID,CredentialID:base64.RawURLEncoding.EncodeToString(parsed.credentialID),COSEKey:base64.RawStdEncoding.EncodeToString(parsed.cose),Algorithm:parsed.algorithm,SignCount:parsed.counter,CreatedAt:time.Now().UTC()},nil
}

func (NativeWebAuthn) VerifyAssertion(response,challenge []byte,rpID string,origins []string,requireUV bool,credential WebAuthnCredential)(uint32,error){
	var envelope assertionEnvelope;if decodeBrowserJSON(response,&envelope)!=nil||envelope.Type!="public-key"{return 0,ErrInvalid};rawID,err:=decodeBase64URL(envelope.RawID,16,1024);if err!=nil{return 0,err};expectedID,err:=decodeBase64URL(credential.CredentialID,16,1024);if err!=nil||subtle.ConstantTimeCompare(rawID,expectedID)!=1||envelope.ID!=credential.CredentialID{return 0,ErrInvalid};clientRaw,err:=decodeBase64URL(envelope.Response.ClientDataJSON,16,1<<20);if err!=nil{return 0,err};if err=verifyClientData(clientRaw,"webauthn.get",challenge,rpID,origins);err!=nil{return 0,err};authData,err:=decodeBase64URL(envelope.Response.AuthenticatorData,37,4096);if err!=nil{return 0,err};counter,err:=verifyAssertionAuthData(authData,rpID,requireUV);if err!=nil{return 0,err};signature,err:=decodeBase64URL(envelope.Response.Signature,8,8192);if err!=nil{return 0,err};cose,err:=base64.RawStdEncoding.DecodeString(credential.COSEKey);if err!=nil{return 0,ErrInvalid};clientHash:=sha256.Sum256(clientRaw);signed:=append(append(make([]byte,0,len(authData)+len(clientHash)),authData...),clientHash[:]...);if err=verifyCOSESignature(cose,credential.Algorithm,signed,signature);err!=nil{return 0,err};if credential.SignCount!=0&&counter!=0&&counter<=credential.SignCount{return 0,ErrReplay};return counter,nil
}

func (verifier *Verifier) BeginWebAuthnRegistration(ctx context.Context,principal identity.ID,rpID string)(identity.ID,[]byte,error){
	if verifier==nil||!principal.Valid()||!validRPID(rpID){return "",nil,ErrInvalid};engine:=verifier.webEngine();challenge:=make([]byte,32);if _,err:=randRead(challenge);err!=nil{return "",nil,err};ref,err:=newReference("avw");if err!=nil{return "",nil,err};options,err:=engine.RegistrationOptions(principal,rpID,verifier.config.WebAuthnDisplayName,challenge,verifier.config.RequireUserVerification);if err!=nil{return "",nil,err};now:=verifier.now();expires:=now.Add(5*time.Minute);payload,_:=json.Marshal(map[string]any{"rp_id":rpID,"challenge_id":ref.String()});tx,err:=verifier.db.BeginTx(ctx,nil);if err!=nil{return "",nil,err};defer tx.Rollback();if _,err=tx.ExecContext(ctx,`INSERT INTO authn_verifiers_v1(ref,principal_id,kind,state,version,payload,created_at,updated_at,last_step) VALUES(?,?,'webauthn','pending',1,?,?,?,-1)`,ref,principal,payload,now,now);err!=nil{return "",nil,err};if _,err=tx.ExecContext(ctx,`INSERT INTO authn_webauthn_challenges_v1(id,principal_id,kind,rp_id,challenge,expires_at) VALUES(?,?,'registration',?,?,?)`,ref,principal,rpID,challenge,expires);err!=nil{return "",nil,err};if err=tx.Commit();err!=nil{return "",nil,err};return ref,options,nil
}

func (verifier *Verifier) FinishWebAuthnRegistration(ctx context.Context,ref identity.ID,response []byte)([]byte,error){
	if verifier==nil||!ref.Valid()||len(response)==0||len(response)>2<<20{return nil,ErrInvalid};record,err:=verifier.load(ctx,ref,"webauthn");if err!=nil{return nil,err};if record.state!="pending"{return nil,ErrConflict};challenge,rpID,err:=verifier.challenge(ctx,ref,record.principal,"registration");if err!=nil{return nil,err};credential,err:=verifier.webEngine().FinishRegistration(response,challenge,rpID,verifier.origins(rpID),verifier.config.RequireUserVerification);if err!=nil{return nil,err};credential.PrincipalID=record.principal;serialized,err:=json.Marshal(credential);if err!=nil{return nil,err};credentialID,err:=base64.RawURLEncoding.DecodeString(credential.CredentialID);if err!=nil{return nil,ErrInvalid};now:=verifier.now();tx,err:=verifier.db.BeginTx(ctx,nil);if err!=nil{return nil,err};defer tx.Rollback();result,err:=tx.ExecContext(ctx,`UPDATE authn_webauthn_challenges_v1 SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?`,now,ref,now);if err!=nil{return nil,err};changed,_:=result.RowsAffected();if changed!=1{return nil,ErrReplay};result,err=tx.ExecContext(ctx,`UPDATE authn_verifiers_v1 SET state='active',payload=?,updated_at=? WHERE ref=? AND state='pending' AND version=?`,serialized,now,ref,record.version);if err!=nil{return nil,err};changed,_=result.RowsAffected();if changed!=1{return nil,ErrConflict};if _,err=tx.ExecContext(ctx,`INSERT INTO authn_webauthn_index_v1(credential_id,ref) VALUES(?,?)`,credentialID,ref);err!=nil{return nil,err};if err=tx.Commit();err!=nil{return nil,err};public:=append([]byte(nil),serialized...);return public,nil
}

func (verifier *Verifier) BeginWebAuthnAssertion(ctx context.Context,principal identity.ID,rpID string)(identity.ID,[]byte,error){
	if verifier==nil||!principal.Valid()||!validRPID(rpID){return "",nil,ErrInvalid};rows,err:=verifier.db.QueryContext(ctx,`SELECT payload FROM authn_verifiers_v1 WHERE principal_id=? AND kind='webauthn' AND state='active' ORDER BY ref`,principal);if err!=nil{return "",nil,err};defer rows.Close();credentials:=make([]WebAuthnCredential,0,8);for rows.Next(){var raw []byte;if err=rows.Scan(&raw);err!=nil{return "",nil,err};var credential WebAuthnCredential;if strictJSON(raw,&credential)!=nil||credential.PrincipalID!=principal||credential.RPID!=rpID{return "",nil,ErrUnavailable};credentials=append(credentials,credential);if len(credentials)>256{return "",nil,ErrInvalid}};if err=rows.Err();err!=nil{return "",nil,err};if len(credentials)==0{return "",nil,ErrNotFound};challenge:=make([]byte,32);if _,err=randRead(challenge);err!=nil{return "",nil,err};challengeID,err:=newReference("wac");if err!=nil{return "",nil,err};options,err:=verifier.webEngine().AssertionOptions(rpID,challenge,credentials,verifier.config.RequireUserVerification);if err!=nil{return "",nil,err};now:=verifier.now();_,err=verifier.db.ExecContext(ctx,`INSERT INTO authn_webauthn_challenges_v1(id,principal_id,kind,rp_id,challenge,expires_at) VALUES(?,?,'assertion',?,?,?)`,challengeID,principal,rpID,challenge,now.Add(5*time.Minute));if err!=nil{return "",nil,err};return challengeID,options,nil
}

func (verifier *Verifier) FinishWebAuthnAssertion(ctx context.Context,challengeID identity.ID,response []byte)(identity.ID,bool,error){
	if verifier==nil||!challengeID.Valid()||len(response)==0||len(response)>2<<20{return "",false,ErrInvalid};var envelope assertionEnvelope;if decodeBrowserJSON(response,&envelope)!=nil{return "",false,ErrInvalid};credentialID,err:=decodeBase64URL(envelope.RawID,16,1024);if err!=nil{return "",false,err};var ref identity.ID;err=verifier.db.QueryRowContext(ctx,`SELECT ref FROM authn_webauthn_index_v1 WHERE credential_id=?`,credentialID).Scan(&ref);if errors.Is(err,sql.ErrNoRows){return "",false,ErrNotFound};if err!=nil{return "",false,err};record,err:=verifier.load(ctx,ref,"webauthn");if err!=nil{return "",false,err};if err=verifier.checkUsable(record);err!=nil{return "",false,err};challenge,rpID,err:=verifier.challenge(ctx,challengeID,record.principal,"assertion");if err!=nil{return "",false,err};var credential WebAuthnCredential;if strictJSON(record.payload,&credential)!=nil||credential.PrincipalID!=record.principal{return "",false,ErrUnavailable};counter,err:=verifier.webEngine().VerifyAssertion(response,challenge,rpID,verifier.origins(rpID),verifier.config.RequireUserVerification,credential);if err!=nil{return "",false,err};credential.SignCount=counter;serialized,_:=json.Marshal(credential);now:=verifier.now();tx,err:=verifier.db.BeginTx(ctx,nil);if err!=nil{return "",false,err};defer tx.Rollback();result,err:=tx.ExecContext(ctx,`UPDATE authn_webauthn_challenges_v1 SET consumed_at=? WHERE id=? AND principal_id=? AND consumed_at IS NULL AND expires_at>?`,now,challengeID,record.principal,now);if err!=nil{return "",false,err};changed,_:=result.RowsAffected();if changed!=1{return "",false,ErrReplay};result,err=tx.ExecContext(ctx,`UPDATE authn_verifiers_v1 SET payload=?,updated_at=? WHERE ref=? AND version=? AND state='active'`,serialized,now,ref,record.version);if err!=nil{return "",false,err};changed,_=result.RowsAffected();if changed!=1{return "",false,ErrConflict};if err=tx.Commit();err!=nil{return "",false,err};return ref,true,nil
}

func (verifier *Verifier) VerifyWebAuthn(ctx context.Context,ref identity.ID,response []byte)(bool,error){var envelope assertionRequestEnvelope;if strictJSON(response,&envelope)!=nil{return false,ErrInvalid};resolved,ok,err:=verifier.FinishWebAuthnAssertion(ctx,envelope.ChallengeID,envelope.Credential);return ok&&resolved==ref,err}
func (verifier *Verifier) challenge(ctx context.Context,id,principal identity.ID,kind string)([]byte,string,error){var challenge []byte;var rpID string;var expires time.Time;var consumed sql.NullTime;err:=verifier.db.QueryRowContext(ctx,`SELECT challenge,rp_id,expires_at,consumed_at FROM authn_webauthn_challenges_v1 WHERE id=? AND principal_id=? AND kind=?`,id,principal,kind).Scan(&challenge,&rpID,&expires,&consumed);if errors.Is(err,sql.ErrNoRows){return nil,"",ErrNotFound};if err!=nil{return nil,"",err};if consumed.Valid||!verifier.now().Before(expires)||len(challenge)!=32{return nil,"",ErrReplay};return challenge,rpID,nil}
func (verifier *Verifier) webEngine()WebAuthnEngine{if verifier.webauthn!=nil{return verifier.webauthn};return NativeWebAuthn{}}
func (verifier *Verifier) origins(rpID string)[]string{configured:=verifier.config.WebAuthnOrigins[rpID];if len(configured)>0{return append([]string(nil),configured...)};return []string{"https://"+rpID}}

type parsedRegistration struct{credentialID,cose []byte;algorithm int64;counter uint32}
func parseRegistrationAuthData(data []byte,rpID string,requireUV bool)(parsedRegistration,error){if len(data)<55{return parsedRegistration{},ErrInvalid};if err:=verifyRPAndFlags(data,rpID,requireUV,true);err!=nil{return parsedRegistration{},err};offset:=37+16;length:=int(binary.BigEndian.Uint16(data[offset:offset+2]));offset+=2;if length<16||length>1024||len(data)<offset+length+1{return parsedRegistration{},ErrInvalid};credentialID:=append([]byte(nil),data[offset:offset+length]...);offset+=length;_,consumed,err:=parseCBOR(data[offset:],0);if err!=nil{return parsedRegistration{},err};cose:=append([]byte(nil),data[offset:offset+consumed]...);algorithm,err:=validateCOSEKey(cose);if err!=nil{return parsedRegistration{},err};return parsedRegistration{credentialID:credentialID,cose:cose,algorithm:algorithm,counter:binary.BigEndian.Uint32(data[33:37])},nil}
func verifyAssertionAuthData(data []byte,rpID string,requireUV bool)(uint32,error){if len(data)<37{return 0,ErrInvalid};if err:=verifyRPAndFlags(data,rpID,requireUV,false);err!=nil{return 0,err};return binary.BigEndian.Uint32(data[33:37]),nil}
func verifyRPAndFlags(data []byte,rpID string,requireUV,requireAT bool)error{expected:=sha256.Sum256([]byte(rpID));if subtle.ConstantTimeCompare(data[:32],expected[:])!=1{return ErrInvalid};flags:=data[32];if flags&0x01==0||(requireUV&&flags&0x04==0)||(requireAT&&flags&0x40==0){return ErrInvalid};return nil}
func verifyClientData(raw []byte,kind string,challenge []byte,rpID string,origins []string)error{var value clientData;if decodeBrowserJSON(raw,&value)!=nil||value.Type!=kind||value.CrossOrigin||value.TopOrigin!=""{return ErrInvalid};decoded,err:=decodeBase64URL(value.Challenge,32,32);if err!=nil||subtle.ConstantTimeCompare(decoded,challenge)!=1{return ErrInvalid};parsed,err:=url.Parse(value.Origin);if err!=nil||parsed.Scheme!="https"||parsed.User!=nil||parsed.Path!=""||parsed.RawQuery!=""||parsed.Fragment!=""{return ErrInvalid};allowed:=false;for _,origin:=range origins{if value.Origin==origin{allowed=true;break}};if !allowed||!strings.EqualFold(parsed.Hostname(),rpID){return ErrInvalid};return nil}
func decodeBrowserJSON(raw []byte,target any)error{if len(raw)==0||len(raw)>2<<20{return ErrInvalid};if err:=rejectDuplicateJSON(raw);err!=nil{return err};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return err};if err:=decoder.Decode(&struct{}{});err!=io.EOF{return ErrInvalid};return nil}
func rejectDuplicateJSON(raw []byte)error{decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.UseNumber();if err:=walkJSONValue(decoder,0);err!=nil{return err};if _,err:=decoder.Token();err!=io.EOF{return ErrInvalid};return nil}
func walkJSONValue(decoder *json.Decoder,depth int)error{if depth>32{return ErrInvalid};token,err:=decoder.Token();if err!=nil{return err};delimiter,ok:=token.(json.Delim);if !ok{return nil};switch delimiter{case '{':seen:=map[string]bool{};for decoder.More(){keyToken,err:=decoder.Token();if err!=nil{return err};key,ok:=keyToken.(string);if !ok||seen[key]{return ErrInvalid};seen[key]=true;if err=walkJSONValue(decoder,depth+1);err!=nil{return err}};closing,err:=decoder.Token();if err!=nil||closing!=json.Delim('}'){return ErrInvalid};case '[':for decoder.More(){if err=walkJSONValue(decoder,depth+1);err!=nil{return err}};closing,err:=decoder.Token();if err!=nil||closing!=json.Delim(']'){return ErrInvalid};default:return ErrInvalid};return nil}
func decodeRegistration(value registrationEnvelope)([]byte,[]byte,[]byte,error){rawID,err:=decodeBase64URL(value.RawID,16,1024);if err!=nil{return nil,nil,nil,err};if value.ID!=base64.RawURLEncoding.EncodeToString(rawID){return nil,nil,nil,ErrInvalid};client,err:=decodeBase64URL(value.Response.ClientDataJSON,16,1<<20);if err!=nil{return nil,nil,nil,err};attestation,err:=decodeBase64URL(value.Response.AttestationObject,32,2<<20);return rawID,client,attestation,err}
func decodeBase64URL(value string,minimum,maximum int)([]byte,error){if value==""||len(value)>maximum*2{return nil,ErrInvalid};decoded,err:=base64.RawURLEncoding.DecodeString(value);if err!=nil||len(decoded)<minimum||len(decoded)>maximum||base64.RawURLEncoding.EncodeToString(decoded)!=value{return nil,ErrInvalid};return decoded,nil}
func validRPID(value string)bool{if len(value)<3||len(value)>253||strings.HasPrefix(value,".")||strings.HasSuffix(value,".")||strings.ContainsAny(value,"/:@ "){return false};for _,label:=range strings.Split(value,"."){if label==""||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return false};for _,character:=range label{if !(character>='a'&&character<='z'||character>='0'&&character<='9'||character=='-'){return false}}};return true}
func validOriginForRP(value, rpID string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || !strings.EqualFold(parsed.Hostname(), rpID) || strings.HasSuffix(parsed.Host, ":") { return false }
	if parsed.Port() == "" { return true }
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	return err == nil && port > 0
}
func randRead(value []byte)(int,error){return cryptoRandRead(value)}

type ecdsaSignature struct{R,S *big.Int}
func validateCOSEKey(raw []byte)(int64,error){value,consumed,err:=parseCBOR(raw,0);if err!=nil||consumed!=len(raw){return 0,ErrInvalid};key,ok:=value.(map[any]any);if !ok{return 0,ErrInvalid};algorithm,ok:=integer(key[int64(3)]);if !ok||(algorithm!=-7&&algorithm!=-8&&algorithm!=-257){return 0,ErrInvalid};_,err=publicKeyFromCOSE(key,algorithm);return algorithm,err}
func verifyCOSESignature(raw []byte,algorithm int64,message,signature []byte)error{value,consumed,err:=parseCBOR(raw,0);if err!=nil||consumed!=len(raw){return ErrInvalid};keyMap,ok:=value.(map[any]any);if !ok{return ErrInvalid};key,err:=publicKeyFromCOSE(keyMap,algorithm);if err!=nil{return err};digest:=sha256.Sum256(message);switch typed:=key.(type){case *ecdsa.PublicKey:var parsed ecdsaSignature;rest,err:=asn1.Unmarshal(signature,&parsed);if err!=nil||len(rest)!=0||parsed.R==nil||parsed.S==nil||!ecdsa.Verify(typed,digest[:],parsed.R,parsed.S){return ErrInvalid};case ed25519.PublicKey:if !ed25519.Verify(typed,message,signature){return ErrInvalid};case *rsa.PublicKey:if rsa.VerifyPKCS1v15(typed,crypto.SHA256,digest[:],signature)!=nil{return ErrInvalid};default:return ErrInvalid};return nil}
func publicKeyFromCOSE(key map[any]any,algorithm int64)(any,error){kty,ok:=integer(key[int64(1)]);if !ok{return nil,ErrInvalid};switch algorithm{case -7:crv,_:=integer(key[int64(-1)]);x,xok:=key[int64(-2)].([]byte);y,yok:=key[int64(-3)].([]byte);if kty!=2||crv!=1||!xok||!yok||len(x)!=32||len(y)!=32{return nil,ErrInvalid};point:=&ecdsa.PublicKey{Curve:elliptic.P256(),X:new(big.Int).SetBytes(x),Y:new(big.Int).SetBytes(y)};if !point.Curve.IsOnCurve(point.X,point.Y){return nil,ErrInvalid};return point,nil;case -8:crv,_:=integer(key[int64(-1)]);x,ok:=key[int64(-2)].([]byte);if kty!=1||crv!=6||!ok||len(x)!=ed25519.PublicKeySize{return nil,ErrInvalid};return ed25519.PublicKey(append([]byte(nil),x...)),nil;case -257:n,nok:=key[int64(-1)].([]byte);eBytes,eok:=key[int64(-2)].([]byte);if kty!=3||!nok||!eok||len(n)<256||len(n)>1024||len(eBytes)<1||len(eBytes)>4{return nil,ErrInvalid};e:=0;for _,value:=range eBytes{e=e<<8|int(value)};if e<3||e%2==0{return nil,ErrInvalid};return &rsa.PublicKey{N:new(big.Int).SetBytes(n),E:e},nil};return nil,ErrInvalid}
func integer(value any)(int64,bool){result,ok:=value.(int64);return result,ok}

func parseCBOR(data []byte,depth int)(any,int,error){if depth>16||len(data)==0{return nil,0,ErrInvalid};initial:=data[0];major:=initial>>5;value,header,err:=cborLength(data,initial&31);if err!=nil{return nil,0,err};switch major{case 0:return int64(value),header,nil;case 1:if value>uint64(^uint64(0)>>1){return nil,0,ErrInvalid};return -1-int64(value),header,nil;case 2:if value>uint64(len(data)-header)||value>2<<20{return nil,0,ErrInvalid};return append([]byte(nil),data[header:header+int(value)]...),header+int(value),nil;case 3:if value>uint64(len(data)-header)||value>1<<20{return nil,0,ErrInvalid};text:=string(data[header:header+int(value)]);if !utf8.ValidString(text)||strings.IndexFunc(text,func(character rune)bool{return character<0x20})>=0{return nil,0,ErrInvalid};return text,header+int(value),nil;case 4:if value>4096{return nil,0,ErrInvalid};result:=make([]any,0,value);offset:=header;for index:=uint64(0);index<value;index++{item,used,err:=parseCBOR(data[offset:],depth+1);if err!=nil{return nil,0,err};offset+=used;result=append(result,item)};return result,offset,nil;case 5:if value>256{return nil,0,ErrInvalid};result:=make(map[any]any,value);offset:=header;for index:=uint64(0);index<value;index++{key,used,err:=parseCBOR(data[offset:],depth+1);if err!=nil{return nil,0,err};offset+=used;switch key.(type){case int64,string:default:return nil,0,ErrInvalid};if _,exists:=result[key];exists{return nil,0,ErrInvalid};item,used,err:=parseCBOR(data[offset:],depth+1);if err!=nil{return nil,0,err};offset+=used;result[key]=item};return result,offset,nil;case 7:if initial==0xf4{return false,1,nil};if initial==0xf5{return true,1,nil};if initial==0xf6{return nil,1,nil}};return nil,0,ErrInvalid}
func cborLength(data []byte,additional byte)(uint64,int,error){switch{case additional<24:return uint64(additional),1,nil;case additional==24:if len(data)<2||data[1]<24{return 0,0,ErrInvalid};return uint64(data[1]),2,nil;case additional==25:if len(data)<3{return 0,0,ErrInvalid};value:=binary.BigEndian.Uint16(data[1:3]);if value<=255{return 0,0,ErrInvalid};return uint64(value),3,nil;case additional==26:if len(data)<5{return 0,0,ErrInvalid};value:=binary.BigEndian.Uint32(data[1:5]);if value<=65535{return 0,0,ErrInvalid};return uint64(value),5,nil;case additional==27:if len(data)<9{return 0,0,ErrInvalid};value:=binary.BigEndian.Uint64(data[1:9]);if value<=0xffffffff{return 0,0,ErrInvalid};return value,9,nil};return 0,0,ErrInvalid}

var cryptoRandRead = func(value []byte)(int,error){return rand.Reader.Read(value)}
var _ WebAuthnEngine = NativeWebAuthn{}
